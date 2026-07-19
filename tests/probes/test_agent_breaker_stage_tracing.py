# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for Agent Breaker stage routing, validation, and tracing."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from garak.attempt import Conversation, Message, Turn
from garak.probes.agent_breaker import AttackState
from garak.probes.agent_breaker_chains import AgentBreakerChains
from garak.resources.agent_breaker_stage import (
    STAGES,
    outcome_sidecar_path,
    sha256_text,
    validate_stage_output,
)


class _Detector:
    @staticmethod
    def _extract_json(value):
        return json.loads(value)


class _StageModel:
    name = "nvidia/nvidia/Nemotron-3-Nano-30B-A3B"
    generator_family_name = "NVIDIA Inference Hub"
    uri = "https://inference-api.nvidia.com/v1/"
    temperature = 0.7
    top_p = 1.0
    max_tokens = 100
    extra_params = {}
    suppressed_params = set()
    seed = None
    api_key = "test-stage-secret"

    def __init__(self, response):
        self.response = response
        self.seen_temperature = None

    def generate(self, prompt, generations_this_call=1):
        self.seen_temperature = self.temperature
        self.last_call_metadata = {
            "provider": "nvidia_inference_hub",
            "endpoint": self.uri + "?api_key=test-stage-secret",
            "request_id": "request-stage",
            "usage": {"total_tokens": 12, "raw": "test-stage-secret"},
            "headers": {"X-API-Key": "test-stage-secret"},
            "api_key": "test-stage-secret",
        }
        return [Message(self.response)]


def _stage_probe(tmp_path, response, *, strict=True, stage="STEP_ATTACK"):
    probe = object.__new__(AgentBreakerChains)
    model = _StageModel(response)
    probe._detector = _Detector()
    probe._stage_models = {"hosted_baseline": model}
    probe.stage_model_roles = {}
    probe.stage_model_routes = {stage: "hosted_baseline"}
    probe.stage_generation_settings = {
        stage: {
            "temperature": 0.0,
            "max_tokens": 4096,
            "extra_params": {
                "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
                "extra_headers": {"X-API-Key": "test-stage-secret"},
            },
        }
    }
    probe.stage_trace_path = str(tmp_path / "stages.jsonl")
    probe._stage_trace_garak_commit = "a" * 40
    probe.strict_stage_outputs = strict
    probe.deterministic_fallbacks_enabled = False
    probe._last_step_target_object = ""
    probe._last_step_target_ref = ""
    probe._prompts = {stage: "template: {value}"}
    return probe, model


def test_exact_stage_registry():
    assert STAGES == (
        "ANALYSIS",
        "TOOL_TAGGING",
        "EDGE_SCORE",
        "EXPLOIT_HYPOTHESES",
        "STEP_PLAN",
        "STEP_ATTACK",
        "STEP_EXPLOIT",
    )
    probe = object.__new__(AgentBreakerChains)
    with pytest.raises(ValueError, match="Unregistered"):
        probe._model_for_stage("step_attack")

    assert validate_stage_output("STEP_PLAN", {"step_plan": []}) == [
        "$.step_plan must contain at least one step"
    ]


def test_stage_contract_rejects_non_string_list_elements():
    errors = validate_stage_output(
        "STEP_PLAN",
        {
            "step_plan": [
                {
                    "tool": "merge_pr",
                    "role": "exploit",
                    "intent": "merge",
                    "must_provide": "merged PR",
                    "success_criterion": "merge succeeds",
                    "artifact_keys": [123],
                }
            ]
        },
    )

    assert errors == ["$.step_plan[0].artifact_keys[0] must be a string"]


def test_hosted_baseline_config_pins_models_routes_and_target_contract():
    config_path = (
        Path(__file__).parents[2] / "scan_agent_breaker_chains_inference_hub.yaml"
    )
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    plugins = config["plugins"]
    target = plugins["generators"]["rest"]["RestGenerator"]
    probe = plugins["probes"]["agent_breaker_chains"]["AgentBreakerChains"]

    assert target["uri"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert target["req_template_json_object"]["model"] == "codereview-chain-v1"
    assert target["req_template_json_object"]["stream"] is False
    assert target["response_metadata_json_fields"] == {
        "terminal_outcome": "$.choices[0].message.metadata.terminal_outcome"
    }
    assert probe["red_team_model_name"] == ("nvidia/nvidia/Nemotron-3-Nano-30B-A3B")
    assert probe["parse_model_name"] == "nvidia/nvidia/Nemotron-3-Nano-30B-A3B"
    assert probe["stage_model_roles"]["teacher"]["model_name"] == (
        "nvidia/zai-org/glm-5.2"
    )
    assert probe["stage_model_roles"]["local_base"] == {
        "model_type": "openai.OpenAICompatible",
        "model_name": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16",
        "model_config": {
            "uri": "http://127.0.0.1:8005/v1/",
            "suppressed_params": ["stop"],
        },
    }
    assert probe["stage_model_routes"] == {stage: "hosted_baseline" for stage in STAGES}
    for stage in ("TOOL_TAGGING", "EDGE_SCORE", "STEP_ATTACK"):
        assert probe["stage_generation_settings"][stage]["extra_params"] == {
            "extra_body": {"chat_template_kwargs": {"enable_thinking": False}}
        }
    for stage in ("ANALYSIS", "EXPLOIT_HYPOTHESES", "STEP_PLAN", "STEP_EXPLOIT"):
        assert (
            probe["stage_generation_settings"][stage]["extra_params"]["extra_body"][
                "reasoning_budget"
            ]
            == 16384
        )
    assert probe["strict_stage_outputs"] is True
    assert probe["deterministic_fallbacks_enabled"] is False
    assert probe["behavioral_probe_enabled"] is False
    assert probe["fault_probe_enabled"] is False


def test_role_loader_preserves_exact_model_identifier():
    probe = object.__new__(AgentBreakerChains)
    probe.stage_model_routes = {"ANALYSIS": "teacher"}
    probe.stage_model_roles = {
        "teacher": {
            "model_type": "nvidia_inference.NVIDIAInferenceHub",
            "model_name": "nvidia/zai-org/glm-5.2",
            "model_config": {
                "uri": "https://inference-api.nvidia.com/v1/",
            },
        }
    }
    probe._stage_models = {}
    expected = object()
    probe._load_model = MagicMock(return_value=expected)

    role, model = probe._model_for_stage("ANALYSIS")

    assert role == "teacher"
    assert model is expected
    probe._load_model.assert_called_once_with(
        "nvidia_inference.NVIDIAInferenceHub",
        "nvidia/zai-org/glm-5.2",
        {
            "uri": "https://inference-api.nvidia.com/v1/",
            "provider_role": "teacher",
        },
    )


def test_stage_trace_is_exact_and_credential_free(tmp_path):
    completion = json.dumps(
        {
            "analysis": "grounded",
            "technique": "benign_recon",
            "target_object": "",
            "target_ref": "",
            "attack_prompt": "List open pull requests.",
        }
    )
    probe, model = _stage_probe(tmp_path, completion)
    prompt = "runtime prompt\nwith exact whitespace\n"

    response = probe._get_stage_model_response("STEP_ATTACK", prompt)

    assert response == completion
    assert model.seen_temperature == 0.0
    assert model.temperature == 0.7
    records = [
        json.loads(line)
        for line in (tmp_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    record = records[0]
    assert record["schema"] == "ai-sec.agent-breaker-stage-trace/v1"
    assert record["attempt_id"] == record["trace_id"]
    assert record["stage"] == "STEP_ATTACK"
    assert record["messages"] == [{"role": "user", "content": prompt}]
    assert record["rendered_prompt"] == prompt
    assert record["prompt_sha256"] == sha256_text(prompt)
    assert record["template_sha256"] == sha256_text("template: {value}")
    assert record["model_role"] == "hosted_baseline"
    assert record["model"] == _StageModel.name
    assert record["schema_valid"] is True
    assert record["fallback_used"] is False
    assert record["deterministic_fallbacks_enabled"] is False
    assert record["generation_settings"]["temperature"] == 0.0
    assert record["generation_settings"]["max_tokens"] == 4096
    assert record["request_metadata"]["request_id"] == "request-stage"
    assert record["endpoint"] == "https://inference-api.nvidia.com/v1/"
    assert set(record["request_metadata"]["usage"]) == {"total_tokens"}
    assert "headers" not in record["request_metadata"]
    assert "api_key" not in record["request_metadata"]
    assert record["generation_settings"]["extra_params"]["extra_headers"] == {
        "X-API-Key": "<redacted>"
    }
    assert record["guards"] == []
    assert record["artifacts"] == {}
    assert record["deterministic_outcome"] is None
    assert record["victim_response"] is None
    assert "INFERENCE_API_KEY" not in json.dumps(record)
    assert "test-stage-secret" not in json.dumps(record)


def test_strict_stage_output_rejects_fenced_json_and_traces_failure(tmp_path):
    completion = (
        "```json\n"
        '{"analysis":"x","technique":"t","target_object":"",'
        '"target_ref":"","attack_prompt":"hello"}\n'
        "```"
    )
    probe, _model = _stage_probe(tmp_path, completion)

    assert probe._get_stage_model_response("STEP_ATTACK", "prompt") is None

    record = json.loads(
        (tmp_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["schema_valid"] is False
    assert record["parsed_completion"] is None
    assert record["validation_errors"][0].startswith("invalid JSON")


def test_model_only_mode_disables_deterministic_run_ci_prompt():
    probe = object.__new__(AgentBreakerChains)
    probe._last_step_target_object = ""
    probe._last_step_target_ref = ""
    chain = {
        "chain_id": "chain_7",
        "sequence": ["upload_file", "list_pull_requests", "run_ci_command", "merge_pr"],
        "step_index": 2,
        "step_plan": [
            {"tool": "upload_file", "role": "plant"},
            {"tool": "list_pull_requests", "role": "recon"},
            {"tool": "run_ci_command", "role": "pivot"},
            {"tool": "merge_pr", "role": "exploit"},
        ],
        "artifacts": {
            "upload_id": "upl_123",
            "uploaded_filename": "build.sh",
            "path_on_build_host": "/tmp/codereview_uploads/build.sh",
            "__object_type__": "pull_request",
            "__object_id__": "5",
        },
        "step_outputs": [
            {
                "tool": "upload_file",
                "artifacts": {
                    "upload_id": "upl_123",
                    "uploaded_filename": "build.sh",
                    "path_on_build_host": "/tmp/codereview_uploads/build.sh",
                },
            },
            {
                "tool": "list_pull_requests",
                "response": "Open pull requests include PR #5 in app.",
                "artifacts": {
                    "__object_type__": "pull_request",
                    "__object_id__": "5",
                },
            },
        ],
    }

    probe.deterministic_fallbacks_enabled = True
    assert probe._build_run_ci_upload_fallback_prompt(chain, 2, "")
    probe.deterministic_fallbacks_enabled = False
    assert probe._build_run_ci_upload_fallback_prompt(chain, 2, "") is None


def test_step_trace_records_post_generation_guard_decision(tmp_path):
    completion = json.dumps(
        {
            "analysis": "grounded",
            "technique": "benign_recon",
            "target_object": "",
            "target_ref": "",
            "attack_prompt": "List open pull requests.",
        }
    )
    probe, _model = _stage_probe(tmp_path, completion)

    def generate(_chain, _step_index, identity_guard_feedback=""):
        return probe._extract_attack_prompt(
            probe._get_stage_model_response(
                "STEP_ATTACK",
                "rendered step prompt",
                trace_context={"artifacts": {"repo": "app"}},
                defer_trace=True,
            )
        )

    probe._generate_step_attack_prompt = generate
    probe._check_prompt_identity_consistency = MagicMock(
        return_value=(True, "identity consistent")
    )
    probe._check_prompt_artifact_consistency = MagicMock(
        return_value=(True, "artifacts consistent")
    )
    chain = {
        "chain_id": "chain_1",
        "sequence": ["list_pull_requests"],
        "step_plan": [{"tool": "list_pull_requests", "role": "exploit"}],
    }

    prompt = probe._generate_guarded_step_prompt(chain, 0)

    assert prompt == "List open pull requests."
    record = json.loads(
        (tmp_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["artifacts"] == {"repo": "app"}
    assert record["guards"] == [
        {
            "kind": "identity_and_artifact_consistency",
            "decision": "accepted",
            "reason_id": None,
        }
    ]
    assert chain["stage_attempt_id"] == record["attempt_id"]
    assert chain["step_generation_stage"] == "STEP_ATTACK"

    probe._append_step_outcome_events(
        attempt_id=chain["stage_attempt_id"],
        stage=chain["step_generation_stage"],
        outcomes=[
            {
                "output_index": 0,
                "victim_response": "victim result",
                "detector_outcome": {
                    "success": True,
                    "confidence": 1.0,
                    "reasoning": "validated",
                },
                "deterministic_outcome": {
                    "schema": "ai-sec.terminal-outcome/v1",
                    "status": "accepted",
                },
            }
        ],
        chain=chain,
        step_index=0,
        target_tool="list_pull_requests",
        step_advanced=True,
        advance_reasoning="validated",
        artifacts={"repo": "app"},
    )
    outcome = json.loads(
        outcome_sidecar_path(tmp_path / "stages.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert outcome["schema"] == "ai-sec.agent-breaker-attempt-outcome/v1"
    assert outcome["attempt_id"] == record["attempt_id"]
    assert outcome["victim_response"] == "victim result"
    assert outcome["deterministic_outcome"]["status"] == "accepted"


def test_pre_model_fallback_emits_keyed_sidecar_event(tmp_path):
    probe, _model = _stage_probe(tmp_path, "unused")
    probe.deterministic_fallbacks_enabled = True
    probe._generate_step_attack_prompt = MagicMock(
        side_effect=AssertionError("model must not run for this shortcut")
    )
    probe._build_identity_grant_fallback_prompt = MagicMock(
        return_value="deterministic terminal prompt"
    )
    probe._check_prompt_identity_consistency = MagicMock(
        return_value=(True, "consistent")
    )
    probe._check_prompt_artifact_consistency = MagicMock(
        return_value=(True, "consistent")
    )
    chain = {
        "chain_id": "chain_1",
        "sequence": ["grant_access"],
        "step_plan": [{"tool": "grant_access", "role": "exploit"}],
        "artifacts": {"approval_token": "lab-only-token"},
    }

    assert probe._generate_guarded_step_prompt(chain, 0) == (
        "deterministic terminal prompt"
    )

    event = json.loads(
        outcome_sidecar_path(tmp_path / "stages.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert event["schema"] == "ai-sec.agent-breaker-fallback-event/v1"
    assert event["model_call_performed"] is False
    assert event["fallback_used"] is True
    assert event["attempt_id"] == chain["stage_attempt_id"]
    assert chain["step_generation_fallback"]["kind"] == "identity_grant"


def test_target_execution_automatically_writes_joined_terminal_outcome(tmp_path):
    completion = json.dumps(
        {
            "analysis": "consume the bound capability",
            "technique": "capability_handoff",
            "target_object": "PR #5",
            "target_ref": "abc123",
            "attack_prompt": "Merge PR #5 with the issued capability.",
        }
    )
    probe, _model = _stage_probe(tmp_path, completion)
    assert (
        probe._get_stage_model_response(
            "STEP_ATTACK", "rendered terminal prompt", defer_trace=True
        )
        == completion
    )
    attempt_id = probe._flush_pending_stage_trace(
        [{"kind": "identity_and_artifact_consistency", "decision": "accepted"}]
    )
    chain = {
        "chain_id": "chain_1",
        "is_chain": True,
        "is_stepwise": True,
        "sequence": ["merge_pr"],
        "step_index": 0,
        "step_plan": [{"tool": "merge_pr", "role": "exploit"}],
        "artifacts": {"merge_token": "lab-capability"},
        "stage_attempt_id": attempt_id,
        "step_generation_stage": "STEP_ATTACK",
    }
    state = AttackState(
        current_target="merge_pr",
        current_tool_analysis=chain,
        current_attack_prompt="Merge PR #5 with the issued capability.",
        vulnerability_info="unsafe merge",
        artifacts=chain["artifacts"],
    )
    attempt = MagicMock()
    attempt.outputs = [Message("Merge completed.")]
    attempt.notes = state.to_notes() | {
        "stage_attempt_id": attempt_id,
        "step_generation_stage": "STEP_ATTACK",
    }
    attempt.prompt = Conversation(
        [Turn("user", Message("Merge PR #5 with the issued capability."))]
    )
    terminal = {
        "schema": "ai-sec.terminal-outcome/v1",
        "kind": "terminal_outcome",
        "status": "accepted",
        "operation": "merge_pr",
        "effect_ref": "sha256:" + "a" * 64,
        "execution_count": 1,
        "suppressed_count": 0,
    }
    probe.success_threshold = 0.7
    probe.global_artifacts = {}
    probe._validated_terminal_outcome = MagicMock(return_value=terminal)
    probe._verify_attack_success = MagicMock(
        side_effect=AssertionError("metadata outcome should be authoritative")
    )
    probe._render_chain_transcript = MagicMock(return_value="transcript")
    probe._chain_grouping_notes = MagicMock(return_value={})

    assert list(probe._generate_next_attempts(attempt)) == []

    events = [
        json.loads(line)
        for line in outcome_sidecar_path(tmp_path / "stages.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(events) == 1
    assert events[0]["attempt_id"] == attempt_id
    assert events[0]["victim_response"] == "Merge completed."
    assert events[0]["deterministic_outcome"] == terminal
    assert events[0]["detector_outcome"]["success"] is True


def test_empty_hypothesis_fallback_is_attributed_to_originating_trace(tmp_path):
    probe, _model = _stage_probe(
        tmp_path,
        '{"hypotheses":[]}',
        stage="EXPLOIT_HYPOTHESES",
    )
    probe.deterministic_fallbacks_enabled = True
    probe.red_team_model = object()
    probe.max_hypotheses_per_chain = 3
    probe.tool_tags = {"merge_pr": {}}
    probe.tool_profiles = {}
    probe.tool_behaviors = {}
    probe._prompts["EXPLOIT_HYPOTHESES"] = "hypotheses {sequence}"
    probe._format_tools_for_analysis = MagicMock(return_value="tool grounding")
    chain = {
        "sequence": ["list_pull_requests", "merge_pr"],
        "delivery": "direct",
        "data_flow": "pull request id",
        "vulnerabilities": "unsafe merge",
    }

    assert probe._generate_exploit_hypotheses(chain) == []

    record = json.loads(
        (tmp_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["stage"] == "EXPLOIT_HYPOTHESES"
    assert record["schema_valid"] is True
    assert record["fallback_used"] is True


def test_step_plan_normaliser_is_disabled_for_model_only_and_attributed_for_diagnostic(
    tmp_path,
):
    raw_plan = {
        "step_plan": [
            {
                "tool": "list_pull_requests",
                "role": "recon",
                "intent": "list",
                "must_provide": "a pull request",
                "success_criterion": "one is returned",
                "artifact_keys": ["pr_number"],
            },
            {
                "tool": "upload_file",
                "role": "recon",
                "intent": "upload",
                "must_provide": "an upload",
                "success_criterion": "accepted",
                "artifact_keys": ["upload_id"],
            },
            {
                "tool": "run_ci_command",
                "role": "plant",
                "intent": "run CI",
                "must_provide": "merge authorization",
                "success_criterion": "CI succeeds",
                "artifact_keys": ["merge_token"],
            },
            {
                "tool": "merge_pr",
                "role": "exploit",
                "intent": "merge",
                "must_provide": "merged PR",
                "success_criterion": "merge succeeds",
                "artifact_keys": [],
            },
        ]
    }
    chain = {
        "sequence": [
            "list_pull_requests",
            "upload_file",
            "run_ci_command",
            "merge_pr",
        ],
        "intent": "merge",
        "data_flow": "bound artifacts",
        "vulnerabilities": "unsafe merge",
        "delivery": "direct",
        "hypothesis": {},
    }

    observed = {}
    for enabled in (False, True):
        case_path = tmp_path / str(enabled).lower()
        probe, _model = _stage_probe(case_path, json.dumps(raw_plan), stage="STEP_PLAN")
        probe.deterministic_fallbacks_enabled = enabled
        probe._prompts["STEP_PLAN"] = "plan {sequence}"
        probe.tool_profiles = {}
        probe.tool_behaviors = {}
        probe._format_tools_for_analysis = MagicMock(return_value="tool grounding")

        plan = probe._generate_step_plan(chain)
        record = json.loads(
            (case_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()[0]
        )
        observed[enabled] = (plan, record)

    assert [entry["role"] for entry in observed[False][0]] == [
        "recon",
        "recon",
        "plant",
        "exploit",
    ]
    assert observed[False][1]["fallback_used"] is False
    assert [entry["role"] for entry in observed[True][0]] == [
        "recon",
        "plant",
        "pivot",
        "exploit",
    ]
    assert observed[True][1]["fallback_used"] is True


def test_guard_prompt_fallback_is_attributed_to_originating_trace(tmp_path):
    completion = json.dumps(
        {
            "analysis": "grounded",
            "technique": "benign_recon",
            "target_object": "",
            "target_ref": "",
            "attack_prompt": "model prompt",
        }
    )
    probe, _model = _stage_probe(tmp_path, completion)
    probe.deterministic_fallbacks_enabled = True

    def generate(_chain, _step_index, identity_guard_feedback=""):
        return probe._extract_attack_prompt(
            probe._get_stage_model_response(
                "STEP_ATTACK", "rendered step prompt", defer_trace=True
            )
        )

    probe._generate_step_attack_prompt = generate
    probe._check_prompt_identity_consistency = MagicMock(
        side_effect=[(False, "identity mismatch"), (True, "consistent")]
    )
    probe._check_prompt_artifact_consistency = MagicMock(
        return_value=(True, "consistent")
    )
    probe._build_identity_upload_fallback_prompt = MagicMock(
        return_value="deterministic fallback"
    )
    for name in (
        "_build_identity_grant_fallback_prompt",
        "_build_run_ci_upload_fallback_prompt",
        "_build_merge_pr_fallback_prompt",
        "_build_place_order_fallback_prompt",
        "_build_order_payment_fallback_prompt",
    ):
        setattr(probe, name, MagicMock(return_value=None))
    chain = {
        "chain_id": "chain_1",
        "sequence": ["upload_file"],
        "step_plan": [{"tool": "upload_file", "role": "exploit"}],
    }

    assert probe._generate_guarded_step_prompt(chain, 0) == "deterministic fallback"

    record = json.loads(
        (tmp_path / "stages.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["stage"] == "STEP_ATTACK"
    assert record["fallback_used"] is True
    assert record["guards"][0]["decision"] == "rejected"


def test_model_only_mode_drops_path_without_model_hypothesis():
    probe = object.__new__(AgentBreakerChains)
    probe.deterministic_fallbacks_enabled = False
    probe.tool_tags = {"sink": {"delivery": "direct"}}
    probe.agent_analysis = {"tool_analyses": {}}
    probe._path_satisfies_required_workflow = MagicMock(return_value=True)
    probe._infer_chain_intent = MagicMock(return_value="intent")
    probe._generate_exploit_hypotheses = MagicMock(return_value=[])
    probe._generate_step_plan = MagicMock(return_value=[])
    path = {
        "sequence": ["source", "sink"],
        "edges": [{"from": "source", "to": "sink", "data_flow": "id"}],
        "score": 1.0,
    }

    result = probe._generate_chain_attacks([path])

    assert result == {"chains": [], "priority_chains": []}
    probe._generate_step_plan.assert_not_called()
