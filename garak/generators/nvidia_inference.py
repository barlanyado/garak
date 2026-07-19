# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""NVIDIA Inference Hub OpenAI-compatible chat generator."""

import inspect
import json
import logging
import os
import time
from typing import List, Union
from urllib.parse import urlsplit

import openai

from garak.attempt import Conversation, Message
from garak.exception import APIKeyMissingError, GarakException
from garak.generators.openai import OpenAICompatible


class NVIDIAInferenceHub(OpenAICompatible):
    """Call exact model identifiers on NVIDIA Inference Hub.

    Authentication is read from ``INFERENCE_API_KEY``. Response metadata is
    deliberately allow-listed before it is attached to returned messages; HTTP
    request headers and credentials are never copied into garak reports.
    """

    ENV_VAR = "INFERENCE_API_KEY"
    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "temperature": 0.0,
        "top_p": 1.0,
        "uri": "https://inference-api.nvidia.com/v1/",
        "provider_role": "unspecified",
        "max_retries": 2,
        "suppressed_params": {
            "frequency_penalty",
            "presence_penalty",
            "stop",
        },
    }
    generator_family_name = "NVIDIA Inference Hub"
    supports_multiple_generations = False
    _unsafe_attributes = [*OpenAICompatible._unsafe_attributes, "api_key"]

    uri: str
    max_retries: int
    provider_role: str
    suppressed_params: set[str] | list[str]
    extra_params: dict

    _REQUEST_ID_HEADERS = (
        "x-request-id",
        "request-id",
        "nvcf-reqid",
        "x-nv-request-id",
    )
    _RATE_LIMIT_HEADERS = (
        "retry-after",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-tokens",
    )
    _RESERVED_EXTRA_PARAMS = frozenset({"model", "messages", "n", "stream"})

    @staticmethod
    def _credential_key(key: object) -> bool:
        collapsed = "".join(
            character for character in str(key).lower() if character.isalnum()
        )
        return (
            "apikey" in collapsed
            or "authorization" in collapsed
            or "credential" in collapsed
            or "secret" in collapsed
            or collapsed
            in {
                "auth",
                "authentication",
                "cookie",
                "keyenvvar",
                "password",
                "passwd",
                "setcookie",
                "token",
            }
            or collapsed.endswith(
                (
                    "apitoken",
                    "accesstoken",
                    "authtoken",
                    "bearertoken",
                    "refreshtoken",
                )
            )
        )

    @classmethod
    def _contains_inline_credential(
        cls, value: object, *, inside_headers: bool = False
    ) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                if cls._credential_key(key):
                    return True
                nested_headers = inside_headers or str(key).lower() in {
                    "headers",
                    "extra_headers",
                    "default_headers",
                }
                if cls._contains_inline_credential(item, inside_headers=nested_headers):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            return any(
                cls._contains_inline_credential(item, inside_headers=inside_headers)
                for item in value
            )
        if inside_headers and isinstance(value, str):
            return value.lstrip().lower().startswith(("bearer ", "basic "))
        return False

    @staticmethod
    def _validate_uri(uri: object) -> None:
        try:
            parsed = urlsplit(str(uri))
        except ValueError:
            raise ValueError("NVIDIA Inference Hub uri is invalid") from None
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "NVIDIA Inference Hub uri must be credential-free HTTPS "
                "without query or fragment components"
            )

    @classmethod
    def _validate_request_configuration(cls, config: object) -> None:
        if cls._contains_inline_credential(config):
            raise ValueError(
                "NVIDIA Inference Hub credentials must be supplied only "
                "through INFERENCE_API_KEY"
            )
        if isinstance(config, dict) and "uri" in config:
            cls._validate_uri(config["uri"])

    @classmethod
    def _validate_extra_params(cls, extra_params: object) -> None:
        cls._validate_request_configuration(extra_params)
        if isinstance(extra_params, dict):
            reserved = cls._RESERVED_EXTRA_PARAMS.intersection(extra_params)
            if reserved:
                raise ValueError(
                    "NVIDIA Inference Hub extra_params cannot override: "
                    + ", ".join(sorted(reserved))
                )

    def _apply_config(self, config):
        """Reject credential overrides so authentication remains environment-only."""
        self._validate_request_configuration(config)
        if isinstance(config, dict) and "extra_params" in config:
            self._validate_extra_params(config["extra_params"])
        super()._apply_config(config)

    def _load_unsafe(self):
        if getattr(self, "api_key", None) is None:
            self.api_key = os.getenv(self.ENV_VAR)
        if self.api_key is None:
            raise APIKeyMissingError("NVIDIA Inference Hub requires INFERENCE_API_KEY")
        self.client = openai.OpenAI(
            base_url=self.uri,
            api_key=self.api_key,
            max_retries=int(self.max_retries),
        )
        if self.name in ("", None):
            raise ValueError(
                "NVIDIA Inference Hub requires an exact model identifier, "
                "for example nvidia/nvidia/Nemotron-3-Nano-30B-A3B"
            )
        self.generator = self.client.chat.completions

    @staticmethod
    def _serializable_usage(usage: object) -> dict:
        """Return the small, report-safe token accounting subset."""
        if usage is None:
            return {}
        if hasattr(usage, "model_dump"):
            raw = usage.model_dump(exclude_none=True)
        elif isinstance(usage, dict):
            raw = usage
        else:
            raw = {
                key: getattr(usage, key, None)
                for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            }
        safe_keys = {
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_tokens_details",
            "completion_tokens_details",
        }
        try:
            return json.loads(
                json.dumps({key: raw[key] for key in safe_keys if key in raw})
            )
        except (TypeError, ValueError):
            return {}

    def _request_metadata(
        self,
        *,
        latency_ms: float,
        status_code: int | None = None,
        headers: object = None,
        response: object = None,
        error_type: str | None = None,
    ) -> dict:
        """Build an allow-listed metadata record for one hosted request."""
        request_id = None
        rate_limits = {}
        if headers is not None:
            for name in self._REQUEST_ID_HEADERS:
                value = headers.get(name)
                if value:
                    request_id = str(value)
                    break
            for name in self._RATE_LIMIT_HEADERS:
                value = headers.get(name)
                if value is not None:
                    rate_limits[name] = str(value)

        response_id = getattr(response, "id", None) if response is not None else None
        metadata = {
            "provider": "nvidia_inference_hub",
            "provider_role": str(self.provider_role),
            "model": self.name,
            "endpoint": str(self.uri),
            "latency_ms": round(latency_ms, 3),
        }
        if status_code is not None:
            metadata["status_code"] = int(status_code)
        if request_id:
            metadata["request_id"] = request_id
        if response_id:
            metadata["response_id"] = str(response_id)
        returned_model = (
            getattr(response, "model", None) if response is not None else None
        )
        if returned_model:
            metadata["returned_model"] = str(returned_model)
        if response is not None:
            usage = self._serializable_usage(getattr(response, "usage", None))
            if usage:
                metadata["usage"] = usage
        if rate_limits:
            metadata["rate_limits"] = rate_limits
        if error_type:
            metadata["error_type"] = error_type
        return metadata

    def _create_args(self, prompt: Conversation) -> dict:
        """Build one chat-completions request from configured safe parameters."""
        if not isinstance(prompt, Conversation):
            raise TypeError("NVIDIAInferenceHub.generate expects a garak Conversation")
        self._validate_uri(self.uri)
        self._validate_extra_params(self.extra_params)
        create_args = {
            "model": self.name,
            "messages": self._conversation_to_list(prompt),
        }
        for arg in inspect.signature(self.generator.create).parameters:
            if arg in {"model", "messages", "extra_params"}:
                continue
            if hasattr(self, arg) and arg not in self.suppressed_params:
                value = getattr(self, arg)
                if value is not None:
                    create_args[arg] = value
        for key, value in self.extra_params.items():
            create_args[key] = value
        if "n" not in self.suppressed_params:
            create_args["n"] = 1
        return create_args

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        """Generate once while preserving safe request, usage, and reasoning data."""
        if generations_this_call != 1:
            raise ValueError("NVIDIA Inference Hub supports one generation per call")
        if self.client is None:
            self._load_unsafe()

        started = time.monotonic()
        try:
            raw_response = self.generator.with_raw_response.create(
                **self._create_args(prompt)
            )
            response = raw_response.parse()
        except openai.APIStatusError as error:
            metadata = self._request_metadata(
                latency_ms=(time.monotonic() - started) * 1000,
                status_code=error.status_code,
                headers=error.response.headers,
                error_type=error.__class__.__name__,
            )
            self.last_call_metadata = metadata
            logging.error(
                "NVIDIA Inference Hub request failed for %s with status %s",
                self.name,
                error.status_code,
            )
            raise GarakException(
                f"NVIDIA Inference Hub request failed with status {error.status_code}"
            ) from None
        except (openai.APITimeoutError, openai.APIConnectionError) as error:
            metadata = self._request_metadata(
                latency_ms=(time.monotonic() - started) * 1000,
                error_type=error.__class__.__name__,
            )
            self.last_call_metadata = metadata
            logging.error(
                "NVIDIA Inference Hub transport failed for %s: %s",
                self.name,
                error.__class__.__name__,
            )
            raise GarakException(
                f"NVIDIA Inference Hub transport failed: {error.__class__.__name__}"
            ) from None
        except (
            openai.APIResponseValidationError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            metadata = self._request_metadata(
                latency_ms=(time.monotonic() - started) * 1000,
                error_type="malformed_response",
            )
            self.last_call_metadata = metadata
            logging.error("NVIDIA Inference Hub returned a malformed response")
            return [None]

        metadata = self._request_metadata(
            latency_ms=(time.monotonic() - started) * 1000,
            status_code=raw_response.status_code,
            headers=raw_response.headers,
            response=response,
        )
        self.last_call_metadata = metadata
        choices = getattr(response, "choices", None)
        if not choices or len(choices) != 1:
            self.last_call_metadata = metadata | {"error_type": "malformed_response"}
            logging.error(
                "NVIDIA Inference Hub response for %s did not contain one choice",
                self.name,
            )
            return [None]

        returned_model = getattr(response, "model", None)
        if returned_model != self.name:
            self.last_call_metadata = metadata | {"error_type": "model_substitution"}
            logging.error(
                "NVIDIA Inference Hub substituted model %r for requested model %r",
                returned_model,
                self.name,
            )
            raise GarakException(
                "NVIDIA Inference Hub returned a different model identifier"
            )

        choice_message = getattr(choices[0], "message", None)
        content = getattr(choice_message, "content", None)
        if content is None:
            self.last_call_metadata = metadata | {"error_type": "empty_content"}
            return [None]

        notes = {"response_metadata": {"nvidia_inference": metadata}}
        reasoning_content = getattr(choice_message, "reasoning_content", None)
        if reasoning_content:
            notes["reasoning_content"] = str(reasoning_content)
            self.last_reasoning_content = str(reasoning_content)
        else:
            self.last_reasoning_content = None
        return [Message(text=str(content), notes=notes)]


class LocalOpenAICompatible(NVIDIAInferenceHub):
    """Call an exact model on a loopback-only OpenAI-compatible endpoint.

    This provider preserves the same response ID, returned-model, usage, latency,
    and reasoning trace metadata as :class:`NVIDIAInferenceHub`. It supplies a
    fixed non-secret placeholder because the OpenAI client requires a value; no
    hosted credential or environment token is used for the local bridge.
    """

    ENV_VAR = None
    DEFAULT_PARAMS = NVIDIAInferenceHub.DEFAULT_PARAMS | {
        "uri": "http://127.0.0.1:8005/v1/",
        "provider_role": "local_base",
        "max_retries": 0,
    }
    generator_family_name = "Traced local OpenAI-compatible"

    @staticmethod
    def _validate_uri(uri: object) -> None:
        try:
            parsed = urlsplit(str(uri))
        except ValueError:
            raise ValueError("local OpenAI-compatible uri is invalid") from None
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "local OpenAI-compatible uri must be credential-free loopback HTTP "
                "without query or fragment components"
            )

    def _load_unsafe(self):
        self.api_key = "local-not-secret"
        self.client = openai.OpenAI(
            base_url=self.uri,
            api_key=self.api_key,
            max_retries=int(self.max_retries),
        )
        if self.name in ("", None):
            raise ValueError(
                "local OpenAI-compatible provider requires an exact model identifier"
            )
        self.generator = self.client.chat.completions

    def _request_metadata(self, **kwargs) -> dict:
        metadata = super()._request_metadata(**kwargs)
        metadata["provider"] = "local_openai_compatible"
        return metadata


DEFAULT_CLASS = "NVIDIAInferenceHub"
