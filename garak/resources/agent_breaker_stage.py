# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stage contracts and JSONL tracing for Agent Breaker Chains."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit
import uuid

STAGES = (
    "ANALYSIS",
    "TOOL_TAGGING",
    "EDGE_SCORE",
    "EXPLOIT_HYPOTHESES",
    "STEP_PLAN",
    "STEP_ATTACK",
    "STEP_EXPLOIT",
)

STAGE_TEMPLATE_SOURCES = {
    "ANALYSIS": "garak/data/agent_breaker/prompts.yaml",
    "TOOL_TAGGING": "garak/data/agent_breaker_chains/prompts.yaml",
    "EDGE_SCORE": "garak/data/agent_breaker_chains/prompts.yaml",
    "EXPLOIT_HYPOTHESES": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_PLAN": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_ATTACK": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_EXPLOIT": "garak/data/agent_breaker_chains/prompts.yaml",
}

_REQUEST_METADATA_KEYS = frozenset(
    {
        "provider",
        "provider_role",
        "model",
        "endpoint",
        "latency_ms",
        "status_code",
        "request_id",
        "response_id",
        "returned_model",
        "usage",
        "rate_limits",
        "error_type",
    }
)
_USAGE_KEYS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "prompt_tokens_details",
        "completion_tokens_details",
    }
)
_RATE_LIMIT_KEYS = frozenset(
    {
        "retry-after",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-tokens",
    }
)


def sha256_text(value: str) -> str:
    """Hash UTF-8 text without normalising its bytes."""
    return hashlib.sha256(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return repr(value)


def _redact_values(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "<redacted>")
        return value
    if isinstance(value, dict):
        return {key: _redact_values(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_values(item, secrets) for item in value]
    return value


def _safe_endpoint(value: object) -> str | None:
    if value is None:
        return None
    endpoint = str(value)
    try:
        parsed = urlsplit(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return endpoint.split("?", 1)[0].split("#", 1)[0]
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urlunsplit((parsed.scheme, hostname + port, parsed.path, "", ""))
    except ValueError:
        return endpoint.split("?", 1)[0].split("#", 1)[0]


def safe_request_metadata(model: object) -> dict:
    """Allow-list trace metadata and remove any configured credential value."""
    raw = getattr(model, "last_call_metadata", {}) or {}
    if not isinstance(raw, dict):
        return {}
    safe = {
        key: _json_safe(raw[key])
        for key in _REQUEST_METADATA_KEYS
        if key in raw and key not in {"usage", "rate_limits", "endpoint"}
    }
    usage = raw.get("usage")
    if isinstance(usage, dict):
        safe["usage"] = {
            key: _json_safe(usage[key]) for key in _USAGE_KEYS if key in usage
        }
    rate_limits = raw.get("rate_limits")
    if isinstance(rate_limits, dict):
        safe["rate_limits"] = {
            key: _json_safe(value)
            for key, value in rate_limits.items()
            if str(key).lower() in _RATE_LIMIT_KEYS
        }
    if "endpoint" in raw:
        safe["endpoint"] = _safe_endpoint(raw["endpoint"])
    api_key = getattr(model, "api_key", None)
    secrets = (api_key,) if isinstance(api_key, str) and api_key else ()
    return _redact_values(safe, secrets)


def _require_mapping(value: object, path: str, errors: list[str]) -> dict:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return {}
    return value


def _require_list(value: object, path: str, errors: list[str]) -> list:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return []
    return value


def _require_string_list(value: object, path: str, errors: list[str]) -> list:
    items = _require_list(value, path, errors)
    for index, item in enumerate(items):
        if not isinstance(item, str):
            errors.append(f"{path}[{index}] must be a string")
    return items


def validate_stage_output(stage: str, parsed: object) -> list[str]:
    """Validate the stable structural contract for one trainable stage."""
    if stage not in STAGES:
        return [f"unregistered stage: {stage}"]
    errors: list[str] = []
    root = _require_mapping(parsed, "$", errors)
    if errors:
        return errors

    if stage == "ANALYSIS":
        analyses = _require_mapping(
            root.get("tool_analyses"), "$.tool_analyses", errors
        )
        _require_string_list(root.get("priority_targets"), "$.priority_targets", errors)
        for name, analysis in analyses.items():
            item = _require_mapping(analysis, f"$.tool_analyses.{name}", errors)
            for key in ("functionality", "vulnerabilities", "exploit_strategies"):
                if not isinstance(item.get(key), str):
                    errors.append(f"$.tool_analyses.{name}.{key} must be a string")
            _require_string_list(
                item.get("attack_prompts"),
                f"$.tool_analyses.{name}.attack_prompts",
                errors,
            )
    elif stage == "TOOL_TAGGING":
        tags = _require_mapping(root.get("tool_tags"), "$.tool_tags", errors)
        for name, tag_record in tags.items():
            item = _require_mapping(tag_record, f"$.tool_tags.{name}", errors)
            for key in ("consumes", "produces", "payload_types"):
                _require_string_list(item.get(key), f"$.tool_tags.{name}.{key}", errors)
            if item.get("capability_class") not in {
                "read_sensitive",
                "write_mutate",
                "network_egress",
                "code_exec",
                "auth_identity",
                "irreversible",
            }:
                errors.append(
                    f"$.tool_tags.{name}.capability_class has an invalid value"
                )
            for key in ("is_source", "is_sink", "executes_content"):
                if not isinstance(item.get(key), bool):
                    errors.append(f"$.tool_tags.{name}.{key} must be boolean")
            severity = item.get("sink_severity")
            if isinstance(severity, bool) or not isinstance(severity, int):
                errors.append(f"$.tool_tags.{name}.sink_severity must be an integer")
            elif not 1 <= severity <= 5:
                errors.append(f"$.tool_tags.{name}.sink_severity must be 1-5")
            if item.get("delivery") not in {"direct", "data_channel"}:
                errors.append(f"$.tool_tags.{name}.delivery has an invalid value")
            if not isinstance(item.get("content_handling"), str):
                errors.append(f"$.tool_tags.{name}.content_handling must be a string")
    elif stage == "EDGE_SCORE":
        edges = _require_list(root.get("edges"), "$.edges", errors)
        for index, edge in enumerate(edges):
            item = _require_mapping(edge, f"$.edges[{index}]", errors)
            for key in ("from", "to", "data_flow"):
                if not isinstance(item.get(key), str) or not item.get(key).strip():
                    errors.append(f"$.edges[{index}].{key} must be a non-empty string")
            confidence = item.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                errors.append(f"$.edges[{index}].confidence must be numeric")
            elif not 0.0 <= float(confidence) <= 1.0:
                errors.append(f"$.edges[{index}].confidence must be 0.0-1.0")
    elif stage == "EXPLOIT_HYPOTHESES":
        hypotheses = _require_list(root.get("hypotheses"), "$.hypotheses", errors)
        for index, hypothesis in enumerate(hypotheses):
            item = _require_mapping(hypothesis, f"$.hypotheses[{index}]", errors)
            for key in (
                "technique",
                "description",
                "payload_shape",
                "sink_requirement",
            ):
                if not isinstance(item.get(key), str):
                    errors.append(f"$.hypotheses[{index}].{key} must be a string")
    elif stage == "STEP_PLAN":
        plan = _require_list(root.get("step_plan"), "$.step_plan", errors)
        if not plan:
            errors.append("$.step_plan must contain at least one step")
        exploit_count = 0
        for index, entry in enumerate(plan):
            item = _require_mapping(entry, f"$.step_plan[{index}]", errors)
            for key in ("tool", "intent", "must_provide", "success_criterion"):
                if not isinstance(item.get(key), str):
                    errors.append(f"$.step_plan[{index}].{key} must be a string")
            role = item.get("role")
            if role not in {"recon", "pivot", "plant", "exploit"}:
                errors.append(f"$.step_plan[{index}].role has an invalid value")
            if role == "exploit":
                exploit_count += 1
            _require_string_list(
                item.get("artifact_keys"),
                f"$.step_plan[{index}].artifact_keys",
                errors,
            )
        if plan and (exploit_count != 1 or plan[-1].get("role") != "exploit"):
            errors.append("$.step_plan must end in its only exploit role")
    else:
        for key in (
            "analysis",
            "technique",
            "target_object",
            "target_ref",
            "attack_prompt",
        ):
            if not isinstance(root.get(key), str):
                errors.append(f"$.{key} must be a string")
        if (
            isinstance(root.get("attack_prompt"), str)
            and not root["attack_prompt"].strip()
        ):
            errors.append("$.attack_prompt must be non-empty")
        if stage == "STEP_EXPLOIT" and not isinstance(root.get("new_approach"), str):
            errors.append("$.new_approach must be a string")
    return errors


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def resolve_git_commit(start: Path) -> str:
    """Resolve a checkout's HEAD without invoking git."""
    for candidate in (start, *start.parents):
        marker = candidate / ".git"
        if marker.is_file():
            gitdir_value = _read_text(marker)
            if not gitdir_value or not gitdir_value.startswith("gitdir:"):
                continue
            git_dir = Path(gitdir_value.split(":", 1)[1].strip())
            if not git_dir.is_absolute():
                git_dir = (candidate / git_dir).resolve()
        elif marker.is_dir():
            git_dir = marker
        else:
            continue

        head = _read_text(git_dir / "HEAD")
        if not head:
            continue
        if not head.startswith("ref:"):
            return head
        ref_name = head.split(":", 1)[1].strip()
        ref_roots = [git_dir]
        commondir = _read_text(git_dir / "commondir")
        if commondir:
            common_root = Path(commondir)
            if not common_root.is_absolute():
                common_root = (git_dir / common_root).resolve()
            ref_roots.append(common_root)
        for ref_root in ref_roots:
            direct = _read_text(ref_root / ref_name)
            if direct:
                return direct
            packed = _read_text(ref_root / "packed-refs")
            if packed:
                for line in packed.splitlines():
                    if line.startswith(("#", "^")):
                        continue
                    parts = line.split(" ", 1)
                    if len(parts) == 2 and parts[1] == ref_name:
                        return parts[0]
    return "unknown"


def make_trace_record(
    *,
    stage: str,
    prompt: str,
    template: str,
    model_role: str,
    model: object,
    raw_completion: str | None,
    parsed_completion: object,
    validation_errors: Iterable[str],
    strict_stage_outputs: bool,
    deterministic_fallbacks_enabled: bool,
    fallback_used: bool,
    generation_settings: dict,
    garak_commit: str,
    guards: object = None,
    artifacts: object = None,
    deterministic_outcome: object = None,
    victim_response: str | None = None,
) -> dict:
    """Construct one credential-free, versioned stage trace record."""
    provider_metadata = safe_request_metadata(model)
    reasoning_content = getattr(model, "last_reasoning_content", None)
    validation_errors = list(validation_errors)
    attempt_id = str(uuid.uuid4())
    record = {
        "schema": "ai-sec.agent-breaker-stage-trace/v1",
        "trace_id": attempt_id,
        "attempt_id": attempt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "prompt_key": stage,
        "messages": [{"role": "user", "content": prompt}],
        "rendered_prompt": prompt,
        "prompt_sha256": sha256_text(prompt),
        "template_source": STAGE_TEMPLATE_SOURCES[stage],
        "template_sha256": sha256_text(template),
        "garak_commit": garak_commit,
        "model_role": model_role,
        "provider": provider_metadata.get(
            "provider", getattr(model, "generator_family_name", "unknown")
        ),
        "model": getattr(model, "name", "unknown"),
        "endpoint": provider_metadata.get(
            "endpoint", _safe_endpoint(getattr(model, "uri", None))
        ),
        "generation_settings": generation_settings,
        "raw_completion": raw_completion,
        "parsed_completion": parsed_completion,
        "validation_errors": validation_errors,
        "schema_valid": not bool(validation_errors),
        "strict_stage_outputs": bool(strict_stage_outputs),
        "deterministic_fallbacks_enabled": bool(deterministic_fallbacks_enabled),
        "fallback_used": bool(fallback_used),
        "guards": [] if guards is None else guards,
        "artifacts": {} if artifacts is None else artifacts,
        "deterministic_outcome": deterministic_outcome,
        "victim_response": victim_response,
        "request_metadata": provider_metadata,
    }
    if reasoning_content:
        record["reasoning_content"] = str(reasoning_content)
    return record


def make_fallback_event(
    *,
    stage: str,
    fallback_kind: str,
    deterministic_prompt: str,
    artifacts: object,
    garak_commit: str,
) -> dict:
    """Construct a trace event for a deterministic pre-model prompt shortcut."""
    if stage not in {"STEP_ATTACK", "STEP_EXPLOIT"}:
        raise ValueError(f"Fallback events are not supported for stage {stage}")
    attempt_id = str(uuid.uuid4())
    return {
        "schema": "ai-sec.agent-breaker-fallback-event/v1",
        "event_id": str(uuid.uuid4()),
        "attempt_id": attempt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "garak_commit": garak_commit,
        "model_call_performed": False,
        "fallback_used": True,
        "fallback_kind": fallback_kind,
        "deterministic_prompt": deterministic_prompt,
        "artifacts": {} if artifacts is None else artifacts,
    }


def make_outcome_event(
    *,
    attempt_id: str,
    stage: str,
    output_index: int,
    victim_response: str | None,
    detector_outcome: dict,
    deterministic_outcome: object,
    step_advanced: bool,
    advance_reasoning: str,
    artifacts: object,
    chain_id: str,
    step_index: int,
    target_tool: str,
) -> dict:
    """Construct a victim/detector sidecar event keyed to one stage row."""
    if stage not in {"STEP_ATTACK", "STEP_EXPLOIT"}:
        raise ValueError(f"Outcome events are not supported for stage {stage}")
    return {
        "schema": "ai-sec.agent-breaker-attempt-outcome/v1",
        "event_id": str(uuid.uuid4()),
        "attempt_id": attempt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "output_index": int(output_index),
        "victim_response": victim_response,
        "detector_outcome": detector_outcome,
        "deterministic_outcome": deterministic_outcome,
        "step_advanced": bool(step_advanced),
        "advance_reasoning": advance_reasoning,
        "artifacts": {} if artifacts is None else artifacts,
        "chain_id": chain_id,
        "step_index": int(step_index),
        "target_tool": target_tool,
    }


def outcome_sidecar_path(stage_trace_path: str | Path) -> Path:
    """Return the deterministic sidecar path for a stage JSONL path."""
    source = Path(stage_trace_path)
    return source.with_name(f"{source.stem}.outcomes{source.suffix}")


def append_trace(path: str | Path, record: dict) -> None:
    """Append one complete JSON object to a UTF-8 JSONL trace."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with destination.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded + "\n")


def append_outcome(stage_trace_path: str | Path, record: dict) -> None:
    """Append an event to the outcome sidecar paired with a stage trace."""
    append_trace(outcome_sidecar_path(stage_trace_path), record)
