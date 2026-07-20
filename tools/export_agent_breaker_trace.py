#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render Agent Breaker stage and outcome JSONL as Markdown or plain text."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable


def _read_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number} is not a JSON object")
        rows.append(value)
    return rows


def _default_outcome_path(trace_path: Path) -> Path:
    if trace_path.name.endswith(".jsonl"):
        return trace_path.with_name(f"{trace_path.name[:-6]}.outcomes.jsonl")
    return trace_path.with_name(f"{trace_path.name}.outcomes.jsonl")


def _json(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def _text(value: object) -> str:
    if value is None:
        return "<null>"
    if isinstance(value, str):
        return value
    return _json(value)


class _Renderer:
    def __init__(self, markdown: bool) -> None:
        self.markdown = markdown
        self.lines: list[str] = []

    def heading(self, level: int, title: str) -> None:
        self.lines.extend([f"{'#' * level} {title}" if self.markdown else title, ""])
        if not self.markdown:
            self.lines.extend(["=" * len(title), ""])

    def paragraph(self, value: str) -> None:
        self.lines.extend([value, ""])

    def field(self, name: str, value: object) -> None:
        label = f"**{name}:**" if self.markdown else f"{name}:"
        self.lines.extend([f"{label} {_text(value)}", ""])

    def block(self, name: str, value: object, language: str = "text") -> None:
        self.paragraph(f"**{name}**" if self.markdown else name)
        body = _text(value)
        if self.markdown:
            fence = "````" if "```" in body else "```"
            self.lines.extend([f"{fence}{language}", body, fence, ""])
        else:
            self.lines.extend([body, ""])

    def render(self) -> str:
        return "\n".join(self.lines).rstrip() + "\n"


def _group_by_attempt(
    outcomes: Iterable[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for outcome in outcomes:
        attempt_id = outcome.get("attempt_id")
        if isinstance(attempt_id, str) and attempt_id:
            grouped.setdefault(attempt_id, []).append(outcome)
    return grouped


def _render_summary(
    renderer: _Renderer,
    traces: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
) -> None:
    models = sorted(
        {str(row["model"]) for row in traces if row.get("model") is not None}
    )
    roles = sorted(
        {
            str(row["model_role"])
            for row in traces
            if row.get("model_role") is not None
        }
    )
    stage_counts = Counter(str(row.get("stage", "<missing>")) for row in traces)
    invalid = sum(not bool(row.get("schema_valid")) for row in traces)
    operational_errors = sum(
        isinstance(row.get("request_metadata"), dict)
        and bool(row["request_metadata"].get("error_type"))
        for row in traces
    )
    renderer.field("Attacker model(s)", models)
    renderer.field("Attacker role(s)", roles)
    renderer.field("Stage trace rows", len(traces))
    renderer.field("Outcome rows", len(outcomes))
    renderer.field("Schema-invalid stage rows", invalid)
    renderer.field("Operational attacker-call errors", operational_errors)
    renderer.block("Stage counts", dict(stage_counts), "json")


def _render_outcome(
    renderer: _Renderer, index: int, outcome: dict[str, Any]
) -> None:
    schema = str(outcome.get("schema", "unknown"))
    renderer.heading(4, f"Joined outcome {index}: {schema}")
    renderer.field("Event ID", outcome.get("event_id"))
    renderer.field("Target tool", outcome.get("target_tool"))
    renderer.field("Step index", outcome.get("step_index"))
    renderer.field("Step advanced", outcome.get("step_advanced"))
    renderer.block("Advance reasoning", outcome.get("advance_reasoning"))
    renderer.block("Victim output", outcome.get("victim_response"))
    renderer.block("Detector outcome", outcome.get("detector_outcome"), "json")
    renderer.block(
        "Deterministic outcome", outcome.get("deterministic_outcome"), "json"
    )
    renderer.block("Artifacts after this turn", outcome.get("artifacts"), "json")
    renderer.block("Complete retained outcome row", outcome, "json")


def _render_trace(
    renderer: _Renderer,
    index: int,
    trace: dict[str, Any],
    outcomes: list[dict[str, Any]],
) -> None:
    stage = str(trace.get("stage", "<missing>"))
    renderer.heading(2, f"{index}. {stage}")
    for name, key in (
        ("Attempt ID", "attempt_id"),
        ("Attacker model", "model"),
        ("Model role", "model_role"),
        ("Provider", "provider"),
        ("Endpoint", "endpoint"),
        ("Timestamp", "timestamp"),
        ("Schema valid", "schema_valid"),
        ("Fallback used", "fallback_used"),
    ):
        renderer.field(name, trace.get(key))
    renderer.block("Exact attacker input", trace.get("rendered_prompt"))
    renderer.block("Exact raw attacker output", trace.get("raw_completion"))
    renderer.block("Parsed attacker output", trace.get("parsed_completion"), "json")
    renderer.block(
        "Provider reasoning content (not consumed by the probe)",
        trace.get("reasoning_content"),
    )
    renderer.block("Validation errors", trace.get("validation_errors"), "json")
    renderer.block("Generation settings", trace.get("generation_settings"), "json")
    renderer.block("Request metadata", trace.get("request_metadata"), "json")
    renderer.block("Guard decisions", trace.get("guards"), "json")
    renderer.block("Artifacts visible at generation", trace.get("artifacts"), "json")
    renderer.block(
        "Deterministic outcome visible at generation",
        trace.get("deterministic_outcome"),
        "json",
    )
    renderer.block(
        "Victim response visible at generation", trace.get("victim_response")
    )
    renderer.block("Complete retained stage row", trace, "json")
    if not outcomes:
        renderer.paragraph("No outcome row was joined to this attacker call.")
    for outcome_index, outcome in enumerate(outcomes, start=1):
        _render_outcome(renderer, outcome_index, outcome)


def _probe_report_rows(report_rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for row in report_rows:
        probe = str(row.get("probe", ""))
        if probe == "agent_breaker_chains.AgentBreakerChains":
            selected.append(row)
            continue
        if row.get("entry_type") == "attempt":
            notes = row.get("notes")
            if isinstance(notes, dict) and notes.get("is_chain"):
                selected.append(row)
    return selected


def render_trace(
    traces: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    report_rows: list[dict[str, Any]],
    episode_summary: dict[str, Any] | None = None,
    *,
    title: str,
    markdown: bool,
) -> str:
    """Render complete retained stage rows and their joined outcomes."""
    renderer = _Renderer(markdown)
    renderer.heading(1, title)
    renderer.paragraph(
        "This file renders retained probe artifacts without reconstructing missing "
        "LLM calls. Provider reasoning is displayed separately because it was "
        "recorded but was not consumed by the probe."
    )
    _render_summary(renderer, traces, outcomes)
    if episode_summary is not None:
        validation = episode_summary.get("validation")
        events = episode_summary.get("events")
        renderer.field(
            "Garak subprocess return code",
            episode_summary.get("subprocess_returncode"),
        )
        renderer.field(
            "Terminal chain valid",
            validation.get("chain_valid") if isinstance(validation, dict) else None,
        )
        event_rows = events.get("events") if isinstance(events, dict) else None
        accepted_operations = [
            event.get("operation")
            for event in event_rows or []
            if isinstance(event, dict)
            and event.get("accepted") is True
            and str(event.get("operation", "")).startswith("tool.")
        ]
        renderer.field("Accepted backend tool operations", accepted_operations)
    outcomes_by_attempt = _group_by_attempt(outcomes)
    for index, trace in enumerate(traces, start=1):
        attempt_id = trace.get("attempt_id")
        joined = outcomes_by_attempt.get(str(attempt_id), [])
        _render_trace(renderer, index, trace, joined)

    selected_report_rows = _probe_report_rows(report_rows)
    if selected_report_rows:
        renderer.heading(2, "Probe report rows")
        for index, row in enumerate(selected_report_rows, start=1):
            renderer.block(f"Report row {index}", row, "json")
    if episode_summary is not None:
        renderer.heading(2, "Episode summary and backend result")
        renderer.block("Complete episode summary", episode_summary, "json")
    return renderer.render()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render Agent Breaker attacker traces and joined outcomes"
    )
    parser.add_argument("trace", type=Path, help="attacker stage JSONL")
    parser.add_argument("output", type=Path, help="output .md or .txt file")
    parser.add_argument(
        "--outcomes",
        type=Path,
        help="outcome JSONL; defaults to TRACE.outcomes.jsonl",
    )
    parser.add_argument("--report", type=Path, help="optional Garak report JSONL")
    parser.add_argument(
        "--episode-summary", type=Path, help="optional one-episode summary JSON"
    )
    parser.add_argument("--title", default="Agent Breaker attacker trace")
    parser.add_argument(
        "--format",
        choices=("markdown", "text"),
        help="defaults to text for .txt output and Markdown otherwise",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Render one trace file."""
    args = _parser().parse_args(argv)
    outcome_path = args.outcomes or _default_outcome_path(args.trace)
    markdown = (
        args.format == "markdown"
        if args.format is not None
        else args.output.suffix.lower() != ".txt"
    )
    rendered = render_trace(
        _read_jsonl(args.trace),
        _read_jsonl(outcome_path),
        _read_jsonl(args.report),
        (
            json.loads(args.episode_summary.read_text(encoding="utf-8"))
            if args.episode_summary is not None
            else None
        ),
        title=args.title,
        markdown=markdown,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
