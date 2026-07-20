# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline episode-export tests."""

import json
from pathlib import Path
import subprocess
import sys


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_exporter_renders_exact_attacker_victim_and_judge_text(tmp_path):
    attempt_id = "attempt-1"
    _write_jsonl(
        tmp_path / "stages.jsonl",
        [{
            "attempt_id": attempt_id,
            "stage": "STEP_ATTACK",
            "rendered_prompt": "exact attacker input",
            "raw_completion": "exact attacker output",
            "parsed_completion": {"attack_prompt": "victim input"},
            "schema_valid": True,
            "validation_errors": [],
        }],
    )
    _write_jsonl(
        tmp_path / "stages.outcomes.jsonl",
        [{
            "attempt_id": attempt_id,
            "victim_response": "exact victim output",
            "judge_trace": {
                "prompt": "exact judge input",
                "raw_completion": "exact judge output",
            },
            "detector_outcome": {"success": False},
            "deterministic_outcome": None,
            "step_advanced": False,
            "advance_reasoning": "not demonstrated",
            "artifacts": {},
        }],
    )
    _write_jsonl(
        tmp_path / "episode.events.jsonl",
        [{
            "sequence_number": 1,
            "kind": "victim_call",
            "stage": "DEEP_RECON",
            "input": "recon input",
            "output": "recon output",
        }],
    )
    output = tmp_path / "episode.md"
    script = Path(__file__).parents[2] / "tools" / "export_agent_breaker_episode.py"

    subprocess.run(
        [
            sys.executable,
            str(script),
            str(tmp_path),
            "--format",
            "markdown",
            "--output",
            str(output),
            "--verify-complete",
        ],
        check=True,
    )

    rendered = output.read_text(encoding="utf-8")
    for expected in (
        "exact attacker input",
        "exact attacker output",
        "exact victim output",
        "exact judge input",
        "exact judge output",
        "recon input",
        "recon output",
    ):
        assert expected in rendered
