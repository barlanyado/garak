# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the NVIDIA Inference Hub generator."""

import json

import httpx
import pytest
import respx

from garak.attempt import Conversation, Message, Turn
from garak.exception import GarakException
from garak.generators.nvidia_inference import NVIDIAInferenceHub

ENDPOINT = "https://inference.invalid/v1/"
MODEL = "nvidia/nvidia/Nemotron-3-Nano-30B-A3B"


def _generator(monkeypatch) -> NVIDIAInferenceHub:
    monkeypatch.setenv("INFERENCE_API_KEY", "test-inference-token")
    config = {
        "generators": {
            "nvidia_inference": {
                "NVIDIAInferenceHub": {
                    "uri": ENDPOINT,
                    "max_retries": 0,
                    "provider_role": "hosted_baseline",
                }
            }
        }
    }
    return NVIDIAInferenceHub(name=MODEL, config_root=config)


def _prompt() -> Conversation:
    return Conversation([Turn("user", Message("Return JSON."))])


def _completion() -> dict:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"ok":true}',
                    "reasoning_content": "bounded reasoning",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3,
            "total_tokens": 8,
        },
    }


def test_exact_model_and_safe_metadata(monkeypatch):
    generator = _generator(monkeypatch)
    with respx.mock(base_url=ENDPOINT) as router:
        route = router.post("chat/completions").mock(
            return_value=httpx.Response(
                200,
                json=_completion(),
                headers={
                    "x-request-id": "request-test",
                    "x-ratelimit-remaining-requests": "7",
                },
            )
        )
        result = generator.generate(_prompt())

    assert result[0].text == '{"ok":true}'
    assert route.calls[0].request.read()
    request_json = json.loads(route.calls[0].request.content)
    assert request_json["model"] == MODEL
    assert request_json["messages"] == [{"role": "user", "content": "Return JSON."}]
    assert result[0].notes["reasoning_content"] == "bounded reasoning"
    metadata = result[0].notes["response_metadata"]["nvidia_inference"]
    assert metadata["request_id"] == "request-test"
    assert metadata["response_id"] == "chatcmpl-test"
    assert metadata["usage"]["total_tokens"] == 8
    assert metadata["provider_role"] == "hosted_baseline"
    assert "test-inference-token" not in json.dumps(result[0].notes)
    assert set(metadata.get("rate_limits", {})) == {"x-ratelimit-remaining-requests"}


def test_api_key_is_removed_from_serialized_state(monkeypatch):
    generator = _generator(monkeypatch)

    state = generator.__getstate__()

    assert state["api_key"] is None
    assert "test-inference-token" not in repr(state)

    restored = object.__new__(NVIDIAInferenceHub)
    restored.__setstate__(state)
    assert restored.api_key == "test-inference-token"


@pytest.mark.parametrize("credential_key", ["api_key", "key_env_var"])
def test_inline_or_alternate_credentials_are_rejected(monkeypatch, credential_key):
    monkeypatch.setenv("INFERENCE_API_KEY", "test-inference-token")
    config = {
        "generators": {
            "nvidia_inference": {
                "NVIDIAInferenceHub": {
                    credential_key: "must-not-be-accepted",
                }
            }
        }
    }

    with pytest.raises(ValueError, match="only through INFERENCE_API_KEY"):
        NVIDIAInferenceHub(name=MODEL, config_root=config)


@pytest.mark.parametrize(
    "bad_extra_params",
    [
        {"extra_headers": {"Authorization": "Bearer inline-secret"}},
        {"extra_query": {"api_key": "inline-secret"}},
        {"default_headers": {"X-API-Key": "inline-secret"}},
    ],
)
def test_nested_credentials_are_rejected(monkeypatch, bad_extra_params):
    monkeypatch.setenv("INFERENCE_API_KEY", "test-inference-token")
    config = {
        "generators": {
            "nvidia_inference": {
                "NVIDIAInferenceHub": {"extra_params": bad_extra_params}
            }
        }
    }

    with pytest.raises(ValueError, match="only through INFERENCE_API_KEY"):
        NVIDIAInferenceHub(name=MODEL, config_root=config)


@pytest.mark.parametrize(
    "uri",
    [
        "https://user:password@inference-api.nvidia.com/v1/",
        "https://inference-api.nvidia.com/v1/?api_key=inline-secret",
        "http://inference-api.nvidia.com/v1/",
    ],
)
def test_endpoint_must_be_credential_free_https(monkeypatch, uri):
    monkeypatch.setenv("INFERENCE_API_KEY", "test-inference-token")
    config = {"generators": {"nvidia_inference": {"NVIDIAInferenceHub": {"uri": uri}}}}

    with pytest.raises(ValueError, match="credential-free HTTPS"):
        NVIDIAInferenceHub(name=MODEL, config_root=config)


@pytest.mark.parametrize("reserved", ["model", "messages", "n", "stream"])
def test_extra_params_cannot_override_core_request_fields(monkeypatch, reserved):
    monkeypatch.setenv("INFERENCE_API_KEY", "test-inference-token")
    config = {
        "generators": {
            "nvidia_inference": {
                "NVIDIAInferenceHub": {"extra_params": {reserved: "override"}}
            }
        }
    }

    with pytest.raises(ValueError, match="cannot override"):
        NVIDIAInferenceHub(name=MODEL, config_root=config)


def test_request_time_validation_blocks_mutated_credentials(monkeypatch):
    generator = _generator(monkeypatch)
    generator.extra_params = {"extra_headers": {"X-API-Key": "runtime-inline-secret"}}

    with pytest.raises(ValueError, match="only through INFERENCE_API_KEY"):
        generator._create_args(_prompt())


@pytest.mark.parametrize("status", [401, 403, 429])
def test_status_errors_are_sanitized(monkeypatch, status):
    generator = _generator(monkeypatch)
    with respx.mock(base_url=ENDPOINT) as router:
        router.post("chat/completions").mock(
            return_value=httpx.Response(
                status,
                json={"error": {"message": "denied", "type": "test"}},
                headers={"x-request-id": f"request-{status}"},
            )
        )
        with pytest.raises(GarakException) as raised:
            generator.generate(_prompt())

    assert str(status) in str(raised.value)
    assert raised.value.__cause__ is None
    assert "test-inference-token" not in str(raised.value)
    assert generator.last_call_metadata["status_code"] == status
    assert generator.last_call_metadata["request_id"] == f"request-{status}"


def test_timeout_is_sanitized(monkeypatch):
    generator = _generator(monkeypatch)
    with respx.mock(base_url=ENDPOINT) as router:
        router.post("chat/completions").mock(side_effect=httpx.ReadTimeout("timed out"))
        with pytest.raises(GarakException) as raised:
            generator.generate(_prompt())

    assert "test-inference-token" not in str(raised.value)
    assert generator.last_call_metadata["error_type"] in {
        "APITimeoutError",
        "APIConnectionError",
    }


def test_malformed_response_returns_none(monkeypatch):
    generator = _generator(monkeypatch)
    with respx.mock(base_url=ENDPOINT) as router:
        router.post("chat/completions").mock(
            return_value=httpx.Response(200, json={"unexpected": True})
        )
        result = generator.generate(_prompt())

    assert result == [None]
    assert generator.last_call_metadata["error_type"] == "malformed_response"


def test_substituted_model_identifier_is_rejected(monkeypatch):
    generator = _generator(monkeypatch)
    completion = _completion()
    completion["model"] = "substituted/model"
    with respx.mock(base_url=ENDPOINT) as router:
        router.post("chat/completions").mock(
            return_value=httpx.Response(200, json=completion)
        )
        with pytest.raises(GarakException, match="different model identifier"):
            generator.generate(_prompt())

    assert generator.last_call_metadata["error_type"] == "model_substitution"
    assert generator.last_call_metadata["returned_model"] == "substituted/model"
    assert "test-inference-token" not in json.dumps(generator.last_call_metadata)
