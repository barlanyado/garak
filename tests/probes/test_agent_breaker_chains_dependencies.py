# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Dependency-graph tests for the evidence-grounded chain pipeline."""

from garak.probes.agent_breaker_chains import AgentBreakerChains


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
        {"from": "list_items", "to": "run_job", "producer_field": "item_id", "consumer_field": "item_id", "confidence": 1.0},
        {"from": "upload_asset", "to": "run_job", "producer_field": "asset_id", "consumer_field": "asset_id", "confidence": 1.0},
        {"from": "run_job", "to": "publish", "producer_field": "approval", "consumer_field": "approval", "confidence": 1.0},
    ]

    paths = probe._search_chains(edges, tags)

    assert len(paths) == 1
    assert set(paths[0]["nodes"]) == set(tags)
    order = paths[0]["sequence"]
    assert order.index("list_items") < order.index("run_job")
    assert order.index("upload_asset") < order.index("run_job")
    assert order.index("run_job") < order.index("publish")


def test_topological_order_accepts_either_sibling_order():
    edges = [
        {"from": "left", "to": "join"},
        {"from": "right", "to": "join"},
        {"from": "join", "to": "sink"},
    ]

    order = AgentBreakerChains._topological_order(
        ["right", "left", "join", "sink"], edges
    )

    assert order in (["left", "right", "join", "sink"], ["right", "left", "join", "sink"])
