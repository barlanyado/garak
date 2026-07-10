"""Tests for narrowly scoped analysis-JSON compatibility handling."""

import json
from unittest.mock import MagicMock

import pytest

from garak.detectors.agent_breaker import AgentBreakerResult
from garak.probes.agent_breaker import AgentBreaker


def _probe() -> AgentBreaker:
    probe = object.__new__(AgentBreaker)
    probe._detector = object.__new__(AgentBreakerResult)
    return probe


def test_extract_analysis_json_normalises_apostrophe_escape():
    probe = _probe()
    analysis = r'''{
        "tool_analyses": {
            "reader": {
                "functionality": "Reads a user\'s file",
                "vulnerabilities": "none",
                "exploit_strategies": "none",
                "attack_prompts": []
            }
        },
        "priority_targets": ["reader"]
    }'''

    parsed = probe._extract_analysis_json(analysis)

    assert parsed["tool_analyses"]["reader"]["functionality"] == "Reads a user's file"
    assert parsed["priority_targets"] == ["reader"]


def test_extract_analysis_json_does_not_repair_other_invalid_escapes():
    probe = _probe()

    with pytest.raises(json.JSONDecodeError):
        probe._extract_analysis_json(r'{"tool_analyses": {"reader": "bad\q"}}')


def test_extract_analysis_json_leaves_valid_json_on_first_parse():
    probe = _probe()
    probe._detector = MagicMock(wraps=object.__new__(AgentBreakerResult))
    analysis = '{"tool_analyses": {}, "priority_targets": []}'

    parsed = probe._extract_analysis_json(analysis)

    assert parsed == {"tool_analyses": {}, "priority_targets": []}
    probe._detector._extract_json.assert_called_once_with(analysis)
