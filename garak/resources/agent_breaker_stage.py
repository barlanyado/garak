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
    "TOOL_INTERFACE_TAGGING",
    "GLOBAL_INTERFACE_BINDING",
    "PATH_ANALYSIS",
    "EXPLOIT_HYPOTHESES",
    "STEP_PLAN",
    "STEP_ATTACK",
    "STEP_EXPLOIT",
)

COMPATIBILITY_STAGES = ("EDGE_SCORE",)
REGISTERED_STAGES = STAGES + COMPATIBILITY_STAGES

STAGE_TEMPLATE_SOURCES = {
    "TOOL_INTERFACE_TAGGING": "garak/data/agent_breaker_chains/prompts.yaml",
    "GLOBAL_INTERFACE_BINDING": "garak/data/agent_breaker_chains/prompts.yaml",
    "EDGE_SCORE": "garak/data/agent_breaker_chains/prompts.yaml",
    "PATH_ANALYSIS": "garak/data/agent_breaker_chains/prompts.yaml",
    "EXPLOIT_HYPOTHESES": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_PLAN": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_ATTACK": "garak/data/agent_breaker_chains/prompts.yaml",
    "STEP_EXPLOIT": "garak/data/agent_breaker_chains/prompts.yaml",
}

TOOL_INTERFACE_CAPABILITY_SEVERITY = {
    "read_sensitive": 3,
    "write_mutate": 3,
    "network_egress": 4,
    "code_exec": 5,
    "auth_identity": 5,
    "financial_transaction": 5,
    "physical_action": 5,
    "irreversible": 5,
    "other_security_impact": 3,
}

TOOL_INTERFACE_REQUIREMENTS = frozenset({"required", "optional", "unknown"})

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
    if stage not in REGISTERED_STAGES:
        return [f"unregistered stage: {stage}"]
    errors: list[str] = []
    root = _require_mapping(parsed, "$", errors)
    if errors:
        return errors

    if stage == "TOOL_INTERFACE_TAGGING":
        item = root
        if item.get("interface_contract_version") != 2:
            errors.append("$.interface_contract_version must be 2")
        for key in ("consumes", "produces"):
            fields = _require_list(item.get(key), f"$.{key}", errors)
            for index, field in enumerate(fields):
                record = _require_mapping(field, f"$.{key}[{index}]", errors)
                for field_key in ("field", "semantic_type", "evidence"):
                    value = record.get(field_key)
                    if not isinstance(value, str) or not value.strip():
                        errors.append(
                            f"$.{key}[{index}].{field_key} must be a non-empty string"
                        )
                field_name = record.get("field")
                if isinstance(field_name, str):
                    if field_name == "$response" and key != "produces":
                        errors.append("$response is allowed only in $.produces")
                    elif field_name.strip().lower() == "unknown":
                        errors.append(
                            f"$.{key}[{index}].field must be an exact field name"
                        )
                if (
                    key == "consumes"
                    and record.get("required") not in TOOL_INTERFACE_REQUIREMENTS
                ):
                    errors.append(
                        f"$.{key}[{index}].required must be required, optional, or unknown"
                    )

        capabilities = _require_list(
            item.get("security_capabilities"), "$.security_capabilities", errors
        )
        for index, capability in enumerate(capabilities):
            record = _require_mapping(
                capability, f"$.security_capabilities[{index}]", errors
            )
            capability_class = record.get("class")
            if capability_class not in TOOL_INTERFACE_CAPABILITY_SEVERITY:
                errors.append(
                    f"$.security_capabilities[{index}].class has an invalid value"
                )
            for key in ("details", "evidence"):
                value = record.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"$.security_capabilities[{index}].{key} must be a non-empty string"
                    )

        controlled = _require_list(
            item.get("attacker_controlled_fields"),
            "$.attacker_controlled_fields",
            errors,
        )
        consumed_names = {
            record.get("field")
            for record in item.get("consumes", [])
            if isinstance(record, dict) and isinstance(record.get("field"), str)
        }
        for index, controlled_field in enumerate(controlled):
            record = _require_mapping(
                controlled_field, f"$.attacker_controlled_fields[{index}]", errors
            )
            for key in ("field", "evidence"):
                value = record.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"$.attacker_controlled_fields[{index}].{key} must be a non-empty string"
                    )
            if record.get("field") not in consumed_names:
                errors.append(
                    f"$.attacker_controlled_fields[{index}].field must name a consumed field"
                )

        for forbidden in (
            "capability_class",
            "attacker_controlled_input",
            "high_impact_action",
            "impact_severity",
            "is_source",
            "is_sink",
            "sink_severity",
        ):
            if forbidden in item:
                errors.append(f"$.{forbidden} is not part of interface contract v2")
    elif stage == "GLOBAL_INTERFACE_BINDING":
        groups = _require_list(
            root.get("artifact_groups"), "$.artifact_groups", errors
        )
        for group_index, group in enumerate(groups):
            group_path = f"$.artifact_groups[{group_index}]"
            group_item = _require_mapping(group, group_path, errors)
            canonical_name = group_item.get("canonical_name")
            if not isinstance(canonical_name, str) or not canonical_name.strip():
                errors.append(f"{group_path}.canonical_name must be a non-empty string")
            flows = _require_list(
                group_item.get("flows"), f"{group_path}.flows", errors
            )
            if not flows:
                errors.append(f"{group_path}.flows must contain at least one flow")
            for flow_index, flow in enumerate(flows):
                flow_path = f"{group_path}.flows[{flow_index}]"
                item = _require_mapping(flow, flow_path, errors)
                producer = _require_mapping(
                    item.get("producer"), f"{flow_path}.producer", errors
                )
                consumer = _require_mapping(
                    item.get("consumer"), f"{flow_path}.consumer", errors
                )
                for key in ("tool", "field"):
                    value = producer.get(key)
                    if not isinstance(value, str) or not value.strip():
                        errors.append(
                            f"{flow_path}.producer.{key} must be a non-empty string"
                        )
                    value = consumer.get(key)
                    if not isinstance(value, str) or not value.strip():
                        errors.append(
                            f"{flow_path}.consumer.{key} must be a non-empty string"
                        )
                member = producer.get("member")
                if not isinstance(member, str):
                    errors.append(f"{flow_path}.producer.member must be a string")
                elif producer.get("field") == "$response" and not member.strip():
                    errors.append(
                        f"{flow_path}.producer.member must name the response member"
                    )
                elif producer.get("field") != "$response" and member.strip():
                    errors.append(
                        f"{flow_path}.producer.member is allowed only for $response"
                    )
                if item.get("support") not in {
                    "documented",
                    "observed",
                    "inferred",
                }:
                    errors.append(f"{flow_path}.support has an invalid value")
                evidence = item.get("evidence")
                if not isinstance(evidence, str) or not evidence.strip():
                    errors.append(f"{flow_path}.evidence must be a non-empty string")

        preconditions = _require_list(
            root.get("state_preconditions"), "$.state_preconditions", errors
        )
        for index, precondition in enumerate(preconditions):
            item = _require_mapping(
                precondition, f"$.state_preconditions[{index}]", errors
            )
            for key in ("before_tool", "after_tool", "support", "evidence"):
                value = item.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"$.state_preconditions[{index}].{key} must be a "
                        "non-empty string"
                    )
            if item.get("support") not in {"documented", "observed"}:
                errors.append(
                    f"$.state_preconditions[{index}].support has an invalid value"
                )
        unresolved = _require_list(
            root.get("unresolved_inputs"), "$.unresolved_inputs", errors
        )
        for index, unresolved_input in enumerate(unresolved):
            item = _require_mapping(
                unresolved_input, f"$.unresolved_inputs[{index}]", errors
            )
            for key in ("tool", "field", "evidence"):
                value = item.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"$.unresolved_inputs[{index}].{key} must be a non-empty string"
                    )
            if item.get("resolution") not in {
                "conversation_controlled",
                "optional",
                "unknown",
            }:
                errors.append(
                    f"$.unresolved_inputs[{index}].resolution has an invalid value"
                )
        if "bindings" in root:
            errors.append(
                "$.bindings is not part of the complete normalization contract"
            )
    elif stage == "EDGE_SCORE":
        edges = _require_list(root.get("edges"), "$.edges", errors)
        for index, edge in enumerate(edges):
            item = _require_mapping(edge, f"$.edges[{index}]", errors)
            for key in (
                "from",
                "to",
                "producer_field",
                "consumer_field",
                "data_flow",
                "evidence",
            ):
                if not isinstance(item.get(key), str) or not item.get(key).strip():
                    errors.append(f"$.edges[{index}].{key} must be a non-empty string")
            confidence = item.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                errors.append(f"$.edges[{index}].confidence must be numeric")
            elif not 0.0 <= float(confidence) <= 1.0:
                errors.append(f"$.edges[{index}].confidence must be 0.0-1.0")
    elif stage == "PATH_ANALYSIS":
        if not isinstance(root.get("summary"), str):
            errors.append("$.summary must be a string")
        claims = _require_list(root.get("claims"), "$.claims", errors)
        for index, claim in enumerate(claims):
            item = _require_mapping(claim, f"$.claims[{index}]", errors)
            if item.get("status") not in {
                "documented",
                "observed",
                "hypothesis",
                "unsupported",
            }:
                errors.append(f"$.claims[{index}].status has an invalid value")
            for key in ("claim", "evidence"):
                if not isinstance(item.get(key), str):
                    errors.append(f"$.claims[{index}].{key} must be a string")
        _require_string_list(root.get("attack_surfaces"), "$.attack_surfaces", errors)
        _require_string_list(root.get("constraints"), "$.constraints", errors)
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
    judge_trace: object = None,
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
        "judge_trace": {} if judge_trace is None else judge_trace,
    }


def make_episode_event(
    *,
    sequence_number: int,
    kind: str,
    stage: str,
    input_data: object,
    output_data: object,
    metadata: object = None,
) -> dict:
    """Construct one ordered, offline-renderable probe event."""
    return {
        "schema": "ai-sec.agent-breaker-episode-event/v1",
        "event_id": str(uuid.uuid4()),
        "sequence_number": int(sequence_number),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "stage": stage,
        "input": _json_safe(input_data),
        "output": _json_safe(output_data),
        "metadata": {} if metadata is None else _json_safe(metadata),
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
