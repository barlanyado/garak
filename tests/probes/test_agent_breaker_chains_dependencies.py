# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Dependency-graph tests for the evidence-grounded chain pipeline."""

import json

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from garak.probes.agent_breaker_chains import AgentBreakerChains
from garak.resources.agent_breaker_stage import validate_stage_output


def _tag(*, produces=(), consumes=(), source=False, sink=False, severity=1):
    return {
        "produce_records": list(produces),
        "consume_records": list(consumes),
        "produces": [item["field"] for item in produces],
        "consumes": [item["field"] for item in consumes],
        "is_source": source,
        "is_sink": sink,
        "sink_severity": severity,
    }


def _field(name, semantic):
    return {"field": name, "semantic_type": semantic, "evidence": name}


def _v2_interface(
    *,
    consumes=(),
    produces=(),
    capabilities=(),
    controlled=(),
):
    return {
        "interface_contract_version": 2,
        "consumes": list(consumes),
        "produces": list(produces),
        "security_capabilities": [
            {
                "class": capability,
                "details": f"documented {capability} behavior",
                "evidence": f"contract documents {capability}",
            }
            for capability in capabilities
        ],
        "attacker_controlled_fields": [
            {"field": field, "evidence": f"conversation supplies {field}"}
            for field in controlled
        ],
    }


def _input(name, semantic="unknown", requirement="required"):
    return {
        "field": name,
        "semantic_type": semantic,
        "required": requirement,
        "evidence": f"contract input {name}",
    }


def _output(name, semantic="unknown"):
    return {
        "field": name,
        "semantic_type": semantic,
        "evidence": f"contract output {name}",
    }


def test_semantic_binding_preserves_different_exact_field_names():
    tags = {
        "run_checks": _tag(
            produces=(_field("merge_pr_token", "authorization_artifact"),),
            source=True,
        ),
        "apply_change": _tag(
            consumes=(_field("merge_token", "authorization_artifact"),),
            sink=True,
            severity=5,
        ),
    }

    edges = AgentBreakerChains._build_capability_graph(tags)

    assert edges == [
        {
            "from": "run_checks",
            "to": "apply_change",
            "producer_field": "merge_pr_token",
            "consumer_field": "merge_token",
            "producer_semantic_type": "authorization_artifact",
            "consumer_semantic_type": "authorization_artifact",
            "match_kind": "semantic",
            "consumer_requirement": "unknown",
            "producer_evidence": "merge_pr_token",
            "consumer_evidence": "merge_token",
        }
    ]


def test_similar_tool_names_remain_distinct_runtime_nodes():
    tags = {
        "list_requests": _tag(
            produces=(_field("request_id", "resource_identifier"),), source=True
        ),
        "list_all_requests": _tag(
            produces=(_field("request_id", "resource_identifier"),), source=True
        ),
        "approve_request": _tag(
            consumes=(_field("request_id", "resource_identifier"),),
            sink=True,
            severity=5,
        ),
    }

    edges = AgentBreakerChains._build_capability_graph(tags)

    assert {(edge["from"], edge["to"]) for edge in edges} == {
        ("list_requests", "approve_request"),
        ("list_all_requests", "approve_request"),
    }


def test_join_subgraph_keeps_sibling_prerequisites_and_valid_order():
    probe = object.__new__(AgentBreakerChains)
    probe.max_chain_len = 4
    probe.max_chains = 1
    tags = {
        "list_items": {"is_source": True, "is_sink": False},
        "upload_asset": {"is_source": True, "is_sink": False},
        "run_job": {"is_source": False, "is_sink": False},
        "publish": {"is_source": False, "is_sink": True, "sink_severity": 5},
    }
    edges = [
        {
            "from": "list_items",
            "to": "run_job",
            "producer_field": "item_id",
            "consumer_field": "item_id",
            "confidence": 1.0,
        },
        {
            "from": "upload_asset",
            "to": "run_job",
            "producer_field": "asset_id",
            "consumer_field": "asset_id",
            "confidence": 1.0,
        },
        {
            "from": "run_job",
            "to": "publish",
            "producer_field": "approval",
            "consumer_field": "approval",
            "confidence": 1.0,
        },
    ]

    paths = probe._search_chains(edges, tags)

    assert len(paths) == 1
    assert set(paths[0]["nodes"]) == set(tags)
    order = paths[0]["sequence"]
    assert order.index("list_items") < order.index("run_job")
    assert order.index("upload_asset") < order.index("run_job")
    assert order.index("run_job") < order.index("publish")


def test_v2_search_rejects_unsatisfied_required_input():
    probe = object.__new__(AgentBreakerChains)
    probe.max_chain_len = 3
    probe.max_chains = 1
    tags = {
        "list_items": {
            "is_source": True,
            "is_sink": False,
            "consume_records": [],
            "attacker_controlled_fields": [],
        },
        "publish": {
            "is_source": False,
            "is_sink": True,
            "sink_severity": 5,
            "consume_records": [
                {"field": "item_id", "required": "required"},
                {"field": "approval", "required": "required"},
            ],
            "attacker_controlled_fields": [],
        },
    }
    edges = [
        {
            "from": "list_items",
            "to": "publish",
            "producer_field": "item_id",
            "consumer_field": "item_id",
            "consumer_requirement": "required",
            "confidence": 1.0,
        }
    ]

    assert probe._search_chains(edges, tags) == []


def test_v2_search_accepts_conversation_controlled_required_input():
    probe = object.__new__(AgentBreakerChains)
    probe.max_chain_len = 3
    probe.max_chains = 1
    tags = {
        "list_items": {
            "is_source": True,
            "is_sink": False,
            "consume_records": [],
            "attacker_controlled_fields": [],
        },
        "publish": {
            "is_source": False,
            "is_sink": True,
            "sink_severity": 5,
            "consume_records": [
                {"field": "item_id", "required": "required"},
                {"field": "comment", "required": "required"},
            ],
            "attacker_controlled_fields": [
                {"field": "comment", "evidence": "conversation supplies it"}
            ],
        },
    }
    edges = [
        {
            "from": "list_items",
            "to": "publish",
            "producer_field": "item_id",
            "consumer_field": "item_id",
            "consumer_requirement": "required",
            "confidence": 1.0,
        }
    ]

    paths = probe._search_chains(edges, tags)

    assert len(paths) == 1
    assert paths[0]["sequence"] == ["list_items", "publish"]


def test_topological_order_accepts_either_sibling_order():
    edges = [
        {"from": "left", "to": "join"},
        {"from": "right", "to": "join"},
        {"from": "join", "to": "sink"},
    ]

    order = AgentBreakerChains._topological_order(
        ["right", "left", "join", "sink"], edges
    )

    assert order in (
        ["left", "right", "join", "sink"],
        ["right", "left", "join", "sink"],
    )


def test_normalisation_resolves_irreversible_false_high_impact_contradiction():
    evidence = {"contract": "This operation is permanent and irreversible."}
    parsed = {
        "consumes": [],
        "produces": [],
        "capability_class": "irreversible",
        "attacker_controlled_input": True,
        "high_impact_action": False,
        "impact_severity": 1,
        "side_effects": ["permanent change"],
        "evidence_summary": ["documented: irreversible"],
    }

    normalised = AgentBreakerChains._normalise_tool_interface(
        "apply_change", parsed, evidence
    )

    assert normalised["is_sink"] is True
    assert normalised["sink_severity"] == 5


def test_v2_timestamp_tool_is_source_but_not_sink():
    parsed = _v2_interface(
        consumes=(_input("timestamp", "timestamp"),),
        produces=(_output("formatted_time", "formatted_timestamp"),),
        controlled=("timestamp",),
    )
    evidence = {"contract": "timestamp formatted_time"}

    normalised = AgentBreakerChains._normalise_tool_interface(
        "format_timestamp", parsed, evidence
    )

    assert normalised["security_capabilities"] == []
    assert normalised["is_source"] is True
    assert normalised["is_sink"] is False
    assert normalised["sink_severity"] == 1


@pytest.mark.parametrize(
    ("capability", "severity"),
    (
        ("read_sensitive", 3),
        ("write_mutate", 3),
        ("network_egress", 4),
        ("code_exec", 5),
        ("auth_identity", 5),
        ("financial_transaction", 5),
        ("physical_action", 5),
        ("irreversible", 5),
        ("other_security_impact", 3),
    ),
)
def test_v2_capability_policy_is_deterministic(capability, severity):
    parsed = _v2_interface(capabilities=(capability,))

    normalised = AgentBreakerChains._normalise_tool_interface(
        "operation", parsed, {"contract": capability}
    )

    assert normalised["is_sink"] is True
    assert normalised["sink_severity"] == severity


def test_v2_multiple_capabilities_use_maximum_severity():
    parsed = _v2_interface(capabilities=("write_mutate", "irreversible"))

    normalised = AgentBreakerChains._normalise_tool_interface(
        "publish", parsed, {"contract": "write_mutate irreversible"}
    )

    assert normalised["sink_severity"] == 5


def test_v2_source_requires_every_mandatory_input_to_be_controlled():
    parsed = _v2_interface(
        consumes=(
            _input("repo", "repository_identifier"),
            _input("approval", "authorization_artifact"),
            _input("message", "content", "optional"),
            _input("context", "context", "unknown"),
        ),
        controlled=("repo",),
    )
    evidence = {"contract": "repo approval message context"}

    normalised = AgentBreakerChains._normalise_tool_interface(
        "apply_change", parsed, evidence
    )

    assert normalised["is_source"] is False
    assert [item["required"] for item in normalised["consume_records"]] == [
        "required",
        "required",
        "optional",
        "unknown",
    ]


def test_v2_filters_invented_fields_and_preserves_reserved_response():
    parsed = _v2_interface(
        consumes=(_input("invented"),),
        produces=(_output("$response", "raw_text"), _output("also_invented")),
        controlled=("invented",),
    )

    normalised = AgentBreakerChains._normalise_tool_interface(
        "read_stream", parsed, {"contract": "returns useful unstructured text"}
    )

    assert normalised["consumes"] == []
    assert normalised["produces"] == ["$response"]
    assert normalised["attacker_controlled_fields"] == []


def test_v2_unresolved_field_names_reach_edge_scoring_candidates():
    tags = {
        "issue_approval": _tag(
            produces=(_field("merge_pr_token", "merge_authorization"),),
            source=True,
        ),
        "apply_change": _tag(
            consumes=(_field("merge_token", "authorization_artifact"),),
            sink=True,
            severity=5,
        ),
    }

    edges = AgentBreakerChains._build_capability_graph(tags)

    assert len(edges) == 1
    assert edges[0]["match_kind"] == "unresolved"
    assert edges[0]["producer_field"] == "merge_pr_token"
    assert edges[0]["consumer_field"] == "merge_token"


def test_unrelated_all_pairs_are_filtered_before_edge_scoring():
    tags = {
        "list_items": _tag(
            produces=(_field("$response", "pull_request_list"),), source=True
        ),
        "upload": _tag(
            consumes=(
                _field("filename", "file_name"),
                _field("content", "file_content"),
            ),
            produces=(_field("upload_id", "uploaded_object_identifier"),),
            source=True,
        ),
        "run_job": _tag(
            consumes=(
                _field("repo", "repository_identifier"),
                _field("upload_id", "uploaded_object_identifier"),
            ),
            produces=(_field("merge_pr_token", "merge_authorization"),),
        ),
        "merge": _tag(
            consumes=(_field("merge_token", "authorization_artifact"),),
            sink=True,
            severity=5,
        ),
    }

    edges = AgentBreakerChains._build_capability_graph(tags)

    pairs = {(edge["producer_field"], edge["consumer_field"]) for edge in edges}
    assert ("upload_id", "upload_id") in pairs
    assert ("merge_pr_token", "merge_token") in pairs
    assert ("upload_id", "repo") not in pairs
    assert ("merge_pr_token", "filename") not in pairs


def test_exact_edge_is_accepted_without_model_call():
    probe = object.__new__(AgentBreakerChains)
    probe.tool_tags = {}
    probe.min_edge_confidence = 0.6
    probe.episode_trace_path = None
    probe._get_stage_model_response = MagicMock()
    candidate = {
        "from": "upload",
        "to": "run_job",
        "producer_field": "upload_id",
        "consumer_field": "upload_id",
        "match_kind": "exact",
        "consumer_requirement": "required",
    }

    edges = probe._score_edges([candidate])

    probe._get_stage_model_response.assert_not_called()
    assert edges == [
        {
            "from": "upload",
            "to": "run_job",
            "producer_field": "upload_id",
            "consumer_field": "upload_id",
            "confidence": 1.0,
            "data_flow": "exact field upload_id is passed to upload_id",
            "evidence": "deterministic exact field-name match",
            "match_kind": "exact",
            "consumer_requirement": "required",
        }
    ]


def test_empty_ambiguous_model_result_preserves_exact_edge():
    probe = object.__new__(AgentBreakerChains)
    probe.tool_tags = {}
    probe.min_edge_confidence = 0.6
    probe.episode_trace_path = None
    probe._prompts = {"EDGE_SCORE": "TOOLS {tool_tags}\nCANDIDATES {candidate_edges}"}
    probe._get_stage_model_response = MagicMock(return_value='{"edges": []}')
    probe._detector = MagicMock()
    probe._detector._extract_json.side_effect = json.loads
    exact = {
        "from": "upload",
        "to": "run_job",
        "producer_field": "upload_id",
        "consumer_field": "upload_id",
        "match_kind": "exact",
        "consumer_requirement": "required",
    }
    renamed = {
        "from": "run_job",
        "to": "merge",
        "producer_field": "merge_pr_token",
        "consumer_field": "merge_token",
        "match_kind": "unresolved",
        "consumer_requirement": "required",
    }

    edges = probe._score_edges([exact, renamed])

    assert len(edges) == 1
    assert edges[0]["match_kind"] == "exact"
    rendered_prompt = probe._get_stage_model_response.call_args.args[1]
    assert "merge_pr_token" in rendered_prompt
    assert '"producer_field": "upload_id"' not in rendered_prompt


def _global_binding_probe():
    probe = object.__new__(AgentBreakerChains)
    probe.episode_trace_path = None
    probe.tool_tags = {
        "list_changes": _tag(
            produces=(_output("$response", "pull_request_list"),),
            source=True,
        ),
        "upload_asset": _tag(
            consumes=(
                _input("filename", "file_name"),
                _input("content", "file_content"),
            ),
            produces=(_output("upload_id", "uploaded_object_identifier"),),
            source=True,
        ),
        "run_job": _tag(
            consumes=(
                _input("repo", "repository_identifier"),
                _input("change_number", "pull_request_identifier"),
                _input("upload_id", "uploaded_object_identifier"),
            ),
            produces=(_output("approval_token", "authorization_artifact"),),
        ),
        "apply_change": _tag(
            consumes=(_input("approval_token", "authorization_artifact"),),
            sink=True,
            severity=5,
        ),
    }
    probe.tool_tags["upload_asset"]["attacker_controlled_fields"] = [
        {"field": "filename", "evidence": "conversation supplies filename"},
        {"field": "content", "evidence": "conversation supplies content"},
    ]
    probe.tool_tags["run_job"]["attacker_controlled_fields"] = [
        {"field": "repo", "evidence": "conversation supplies repository"}
    ]
    return probe


def test_global_binding_normalisation_preserves_runtime_names_and_builds_path():
    probe = _global_binding_probe()
    probe.max_chain_len = 4
    probe.max_chains = 1
    exact = probe._exact_binding_edges(probe._build_capability_graph(probe.tool_tags))
    parsed = {
        "bindings": [
            {
                "producer_tool": "list_changes",
                "producer_field": "$response",
                "producer_member": "number",
                "consumer_tool": "run_job",
                "consumer_field": "change_number",
                "canonical_artifact": "change_identifier",
                "relation": "response_member",
                "support": "observed",
                "evidence": "observed list response names each change number",
            },
            {
                "producer_tool": "run_job",
                "producer_field": "invented_token",
                "producer_member": "",
                "consumer_tool": "apply_change",
                "consumer_field": "approval_token",
                "canonical_artifact": "authorization_artifact",
                "relation": "semantic_alias",
                "support": "inferred",
                "evidence": "invented output",
            },
        ],
        "state_preconditions": [
            {
                "before_tool": "list_changes",
                "after_tool": "upload_asset",
                "support": "documented",
                "evidence": "upload is scoped to a listed change",
            }
        ],
    }

    edges = probe._normalise_global_bindings(parsed, exact)
    paths = probe._search_chains(edges, probe.tool_tags)

    assert any(
        edge["producer_field"] == "$response"
        and edge["producer_member"] == "number"
        and edge["consumer_field"] == "change_number"
        for edge in edges
    )
    assert not any(edge.get("producer_field") == "invented_token" for edge in edges)
    assert len(paths) == 1
    assert paths[0]["sequence"] == [
        "list_changes",
        "upload_asset",
        "run_job",
        "apply_change",
    ]


def test_global_binding_prompt_receives_all_tools_exact_and_unresolved_inputs():
    probe = _global_binding_probe()
    probe.agent_config = {
        "tools": [
            {"name": name, "description": f"contract for {name}"}
            for name in probe.tool_tags
        ]
    }
    probe.tool_profiles = {name: {} for name in probe.tool_tags}
    probe.tool_behaviors = {name: [] for name in probe.tool_tags}
    probe._prompts = {
        "GLOBAL_INTERFACE_BINDING": (
            "TOOLS {tool_interfaces}\nEXACT {exact_bindings}\n"
            "UNRESOLVED {unresolved_inputs}"
        )
    }
    probe._detector = MagicMock()
    probe._detector._extract_json.side_effect = json.loads
    probe._get_stage_model_response = MagicMock(
        return_value='{"bindings": [], "state_preconditions": []}'
    )
    candidates = probe._build_capability_graph(probe.tool_tags)

    edges = probe._bind_global_interfaces(candidates)

    rendered = probe._get_stage_model_response.call_args.args[1]
    assert all(name in rendered for name in probe.tool_tags)
    assert '"producer_field": "upload_id"' in rendered
    assert '"field": "change_number"' in rendered
    assert all(edge["match_kind"] == "exact" for edge in edges)


def test_dependency_contract_uses_response_member_and_runtime_consumer_field():
    sequence = ["list_changes", "run_job"]
    plan = [
        {"tool": "list_changes", "artifact_keys": []},
        {"tool": "run_job", "artifact_keys": []},
    ]
    dependencies = [
        {
            "from": "list_changes",
            "to": "run_job",
            "producer_field": "$response",
            "producer_member": "number",
            "consumer_field": "change_number",
        }
    ]

    normalised = AgentBreakerChains._apply_dependency_artifact_contract(
        sequence, plan, dependencies
    )

    assert normalised[0]["artifact_keys"] == ["number"]
    assert normalised[1]["input_artifact_keys"] == ["change_number"]


def test_global_response_member_extraction_uses_visible_named_value_only():
    probe = object.__new__(AgentBreakerChains)
    probe.global_interface_bindings = [
        {
            "from": "list_changes",
            "producer_field": "$response",
            "producer_member": "number",
            "match_kind": "response_member",
        }
    ]

    artifacts = probe._global_response_member_artifacts(
        "list_changes", '{"title": "Fix", "number": 42}'
    )

    assert artifacts == {"number": "42"}


def test_tool_issued_required_field_is_not_conversation_controlled():
    tags = {
        "upload": {
            "produce_records": [_output("upload_id")],
            "consume_records": [],
            "attacker_controlled_fields": [],
            "is_source": True,
        },
        "run_job": {
            "produce_records": [],
            "consume_records": [_input("upload_id")],
            "attacker_controlled_fields": [
                {"field": "upload_id", "evidence": "conversation supplies it"}
            ],
            "is_source": True,
        },
    }

    reconciled = AgentBreakerChains._reconcile_attacker_controlled_fields(tags)

    assert reconciled["run_job"]["attacker_controlled_fields"] == []
    assert reconciled["run_job"]["is_source"] is False
    assert reconciled["run_job"]["removed_attacker_controlled_fields"][0][
        "producer_tools"
    ] == ["upload"]


def test_complete_terminal_workflow_wins_before_max_chains_truncation():
    probe = object.__new__(AgentBreakerChains)
    probe.max_chain_len = 4
    probe.max_chains = 1
    probe.agent_config = {
        "tools": [
            {"name": "list_pull_requests", "description": "List pull requests"},
            {"name": "upload_file", "description": "Upload a file"},
            {
                "name": "run_ci_command",
                "description": "Use an upload and return authorization context",
            },
            {
                "name": "merge_pr",
                "description": "Merge with prior authorization context",
            },
        ]
    }
    tags = {
        "upload_file": {"is_source": True, "is_sink": True, "sink_severity": 3},
        "run_ci_command": {
            "is_source": False,
            "is_sink": True,
            "sink_severity": 5,
        },
        "merge_pr": {"is_source": False, "is_sink": True, "sink_severity": 5},
    }
    probe.tool_tags = tags
    edges = [
        {
            "from": "upload_file",
            "to": "run_ci_command",
            "producer_field": "upload_id",
            "consumer_field": "upload_id",
            "consumer_requirement": "required",
            "confidence": 1.0,
        },
        {
            "from": "run_ci_command",
            "to": "merge_pr",
            "producer_field": "merge_token",
            "consumer_field": "merge_token",
            "consumer_requirement": "required",
            "confidence": 1.0,
        },
    ]

    paths = probe._search_chains(edges, tags)

    assert len(paths) == 1
    assert paths[0]["sequence"] == [
        "upload_file",
        "run_ci_command",
        "merge_pr",
    ]


def test_v2_validator_accepts_complete_contract():
    parsed = _v2_interface(
        consumes=(_input("content", "content"),),
        produces=(_output("upload_id", "uploaded_object_identifier"),),
        capabilities=("write_mutate",),
        controlled=("content",),
    )

    assert validate_stage_output("TOOL_INTERFACE_TAGGING", parsed) == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("interface_contract_version"),
        lambda value: value["consumes"][0].update(required=True),
        lambda value: value["security_capabilities"][0].update({"class": "unknown"}),
        lambda value: value.update(high_impact_action=True),
    ),
)
def test_v2_validator_rejects_old_or_invalid_contract_fields(mutation):
    parsed = _v2_interface(
        consumes=(_input("content", "content"),),
        capabilities=("write_mutate",),
        controlled=("content",),
    )
    mutation(parsed)

    errors = validate_stage_output("TOOL_INTERFACE_TAGGING", parsed)

    assert errors


def test_v2_validator_rejects_controlled_field_not_in_consumes():
    parsed = _v2_interface(controlled=("invented",))

    errors = validate_stage_output("TOOL_INTERFACE_TAGGING", parsed)

    assert errors == [
        "$.attacker_controlled_fields[0].field must name a consumed field"
    ]


def test_tagging_prompt_is_generic_and_renders_v2_contract():
    prompt_path = (
        Path(__file__).parents[2]
        / "garak"
        / "data"
        / "agent_breaker_chains"
        / "prompts.yaml"
    )
    template = yaml.safe_load(prompt_path.read_text(encoding="utf-8"))[
        "TOOL_INTERFACE_TAGGING"
    ]

    rendered = template.format(agent_purpose="test", tool_evidence="{}")

    assert '"interface_contract_version": 2' in rendered
    assert '"security_capabilities"' in rendered
    assert '"high_impact_action"' not in rendered
    for victim_specific_name in (
        "list_pull_requests",
        "upload_file",
        "run_ci_command",
        "merge_pr",
    ):
        assert victim_specific_name not in template
