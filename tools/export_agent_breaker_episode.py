#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render a complete Agent Breaker episode directory without network calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number} is not a JSON object")
        rows.append(value)
    return rows


def _first(directory: Path, names: tuple[str, ...]) -> Path:
    for name in names:
        candidate = directory / name
        if candidate.exists():
            return candidate
    return directory / names[0]


def _block(title: str, value: object, markdown: bool) -> list[str]:
    body = value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
    if markdown:
        fence = "````" if "```" in body else "```"
        return [f"**{title}**", "", f"{fence}text", body, fence, ""]
    return [title, body, ""]


def _verify(stages: list[dict], events: list[dict], outcomes: list[dict]) -> None:
    errors = []
    sequences = [row.get("sequence_number") for row in events]
    if sequences and sorted(sequences) != list(range(1, len(sequences) + 1)):
        errors.append("episode event sequence numbers are incomplete")
    for index, row in enumerate(stages, 1):
        if not row.get("rendered_prompt"):
            errors.append(f"stage row {index} has no exact input")
        if "raw_completion" not in row:
            errors.append(f"stage row {index} has no raw output field")
    stage_ids = {row.get("attempt_id") for row in stages}
    for index, row in enumerate(outcomes, 1):
        if row.get("attempt_id") not in stage_ids:
            errors.append(f"outcome row {index} cannot be joined to a stage")
        judge = row.get("judge_trace")
        if judge and ("prompt" not in judge or "raw_completion" not in judge):
            errors.append(f"outcome row {index} has an incomplete judge trace")
    if errors:
        raise ValueError("; ".join(errors))


def render(directory: Path, markdown: bool, verify_complete: bool) -> str:
    stage_path = _first(directory, ("stages.jsonl", "stage_trace.jsonl"))
    event_path = _first(directory, ("episode.events.jsonl", "events.jsonl"))
    outcome_path = stage_path.with_name(f"{stage_path.stem}.outcomes{stage_path.suffix}")
    report_path = _first(directory, ("report.jsonl", "garak.report.jsonl"))
    summary_path = _first(directory, ("episode_summary.json", "summary.json"))
    stages = _read_jsonl(stage_path)
    events = _read_jsonl(event_path)
    outcomes = _read_jsonl(outcome_path)
    reports = _read_jsonl(report_path)
    if verify_complete:
        _verify(stages, events, outcomes)

    lines = ["# Agent Breaker episode" if markdown else "Agent Breaker episode", ""]
    lines.extend(_block("Source files", {
        "stages": str(stage_path), "events": str(event_path),
        "outcomes": str(outcome_path), "report": str(report_path),
        "summary": str(summary_path),
    }, markdown))
    lines.extend(_block("Counts", {
        "stage_calls": len(stages), "probe_events": len(events),
        "outcomes": len(outcomes), "report_rows": len(reports),
    }, markdown))

    joined: dict[str, list[dict]] = {}
    for outcome in outcomes:
        joined.setdefault(str(outcome.get("attempt_id")), []).append(outcome)
    for index, row in enumerate(stages, 1):
        heading = f"## {index}. {row.get('stage', 'UNKNOWN')}" if markdown else f"{index}. {row.get('stage', 'UNKNOWN')}"
        lines.extend([heading, ""])
        lines.extend(_block("Prompt input", row.get("rendered_prompt"), markdown))
        lines.extend(_block("Raw model output", row.get("raw_completion"), markdown))
        lines.extend(_block("Parsed output and validation", {
            "parsed": row.get("parsed_completion"),
            "schema_valid": row.get("schema_valid"),
            "validation_errors": row.get("validation_errors"),
            "model": row.get("model"),
            "request_metadata": row.get("request_metadata"),
        }, markdown))
        for outcome in joined.get(str(row.get("attempt_id")), []):
            lines.extend(_block("Victim output", outcome.get("victim_response"), markdown))
            lines.extend(_block("Judge input/output", outcome.get("judge_trace", {}), markdown))
            lines.extend(_block("Deterministic decision", {
                "detector": outcome.get("detector_outcome"),
                "backend": outcome.get("deterministic_outcome"),
                "step_advanced": outcome.get("step_advanced"),
                "reason": outcome.get("advance_reasoning"),
                "artifacts": outcome.get("artifacts"),
            }, markdown))

    if events:
        lines.extend(["## All probe events" if markdown else "All probe events", ""])
        for event in sorted(events, key=lambda row: row.get("sequence_number", 0)):
            lines.extend(_block(
                f"Event {event.get('sequence_number')}: {event.get('kind')} / {event.get('stage')}",
                event,
                markdown,
            ))
    if reports:
        lines.extend(_block("Garak report rows", reports, markdown))
    if summary_path.exists():
        lines.extend(_block("Episode summary and backend events", json.loads(summary_path.read_text(encoding="utf-8")), markdown))
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("episode_dir", type=Path)
    parser.add_argument("--format", choices=("markdown", "text"), default="markdown")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-complete", action="store_true")
    args = parser.parse_args()
    output = render(args.episode_dir, args.format == "markdown", args.verify_complete)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
