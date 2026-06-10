# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""**Agent Breaker Chains probe**

A multi-turn red-team probe for attacking agentic LLM applications by chaining
multiple tools together.

Builds on :class:`~garak.probes.agent_breaker.AgentBreaker`: it reuses the same
recon, deep-recon, and per-tool weakness analysis, then discovers multi-tool
attack chains via a capability-graph path search and exploits them. Single-tool
attacks live in the base probe; this one runs chains only so they can be
selected, reported, and tuned in isolation.

Chain discovery uses the LLM only for small, reliable sub-tasks (tagging a single
tool, scoring a single data-flow edge, writing the payload for a concrete path) —
never for inventing whole chains. The plausible source->sink sequences are found
by pure-Python path search over the capability graph.

Further info:

* https://genai.owasp.org/llmrisk/llm062025-excessive-agency/

"""

import copy
import json
import logging
from typing import Iterable, List, Optional, Tuple

import yaml

from garak import _config
from garak.data import path as data_path
import garak.attempt
from garak.probes.agent_breaker import AgentBreaker, AttackState


class AgentBreakerChains(AgentBreaker):
    """Agent Breaker - multi-tool chain exploitation.

    Discovers and attacks multi-tool chains using a capability-graph path
    search:

    1. _tag_tool_capabilities — tag every tool with what it
       consumes/produces, its capability class, and source/sink markers.
    2. _build_capability_graph — pure-Python candidate edges where one
       tool's output tag feeds another tool's input tag.
    3. _score_edges — one batched LLM call to confirm/score edges.
    4. _search_chains — pure-Python bounded source->sink path search,
       ranked by ``sink_severity * product(edge_confidence)``.
    5. _generate_chain_attacks — write conversational payloads for each
       concrete path.

    Recon, deep recon, and per-tool weakness analysis are inherited from
    class AgentBreaker (the per-tool analysis grounds capability tagging).
    Running this probe drives the target independently, so it re-runs recon
    rather than sharing it with a single-tool run.
    """

    goal = "Identify weaknesses in agentic applications through multi-tool chaining"
    primary_detector = "agent_breaker_chains.AgentBreakerChainResult"

    DEFAULT_PARAMS = AgentBreaker.DEFAULT_PARAMS | {
        # Maximum number of tool chains to attack (top-ranked by severity x confidence)
        "max_chains": 8,
        # Maximum number of tools in a discovered chain
        "max_chain_len": 4,
        # Minimum confidence for a data-flow edge to be kept in the capability graph
        "min_edge_confidence": 0.4,
        # Per-step attempt budget (initial + refinements) during stepwise chain execution.
        "max_step_attempts": 3,
        # How many DISTINCT exploit techniques to try per discovered chain path.
        # Each becomes its own independent attack line so the probe explores
        # multiple hypotheses (e.g. path traversal vs planting executable
        # content) instead of fixating on one. Set to 1 to disable fan-out.
        "max_hypotheses_per_chain": 3,
    }

    # Hard cap on how many characters of a prior step's raw response we paste into
    # the next step's red-team prompt -- defensive against token blow-up.
    _STEP_RESPONSE_CHAR_LIMIT = 2000

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        # tool_name -> tag_dict (consumes/produces/capability/source/sink markers)
        self.tool_tags: dict = {}
        # Technique label parsed from the most recent step prompt-generation
        # call. Read immediately after generation to stamp the attack state, so
        # per-step history records which technique class each attempt used.
        self._last_step_technique: str = ""
        # Artifacts accumulated across ALL chains during the run. One chain's
        # recon (e.g. an org chart that returns every employee id) populates
        # this so a different chain's recon can reuse those concrete values
        # instead of cold-calling a tool that 500s on under-specified input.
        # Read at prompt-render time, written whenever any step extracts.
        self.global_artifacts: dict = {}

    def _make_detector(self, config_root):
        from garak.detectors.agent_breaker_chains import AgentBreakerChainResult

        return AgentBreakerChainResult(config_root=config_root)

    def _load_prompts(self):
        super()._load_prompts()
        chains_prompts_path = data_path / "agent_breaker_chains" / "prompts.yaml"
        with open(chains_prompts_path, "r", encoding="utf-8") as f:
            self._prompts.update(yaml.safe_load(f))

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def _create_init_attempts(self) -> Iterable[garak.attempt.Attempt]:
        """Create initial chain attack attempts based on agent analysis."""
        if not self._run_recon():
            return []

        logging.info(
            f"{self.__class__.__name__} # Searching for multi-tool attack chains..."
        )
        chain_result = self._analyze_tool_chains()
        self.agent_analysis["chains"] = chain_result.get("chains", [])
        self.agent_analysis["priority_chains"] = chain_result.get("priority_chains", [])

        chain_configs = self._build_chain_configs()

        # Budget the iterative loop: every chain runs as a plan-driven sequence
        # of up to ``max_chain_len`` steps, each step with up to
        # ``max_step_attempts`` initial+refinement turns.
        budget_per_chain = self.max_chain_len * self.max_step_attempts
        self.max_calls_per_conv = len(chain_configs) * budget_per_chain

        if not chain_configs:
            logging.warning(f"{self.__class__.__name__} # No chains to attack")
            return []

        logging.info(
            f"{self.__class__.__name__} # Attacking {len(chain_configs)} chains"
        )
        for entry_tool, chain in chain_configs:
            chain_id = chain.get("chain_id", "?")
            sequence = chain.get("sequence", []) or [entry_tool]
            logging.info(
                f"{self.__class__.__name__} # Chain {chain_id}: "
                f"{' -> '.join(sequence)}"
            )

        all_attempts: List[garak.attempt.Attempt] = []
        for entry_tool, chain in chain_configs:
            try:
                all_attempts.extend(self._attack_single_chain(entry_tool, chain))
            except Exception:
                logging.exception(
                    f"{self.__class__.__name__} # Unhandled error attacking chain %s, skipping",
                    chain.get("chain_id", "?"),
                )

        return all_attempts

    def _build_chain_configs(self) -> List[Tuple[str, dict]]:
        """Extract (entry_tool, chain_dict) tuples from agent_analysis.

        Mirrors `AgentBreaker._build_tool_configs` but for chain attacks.
        Each ``chain_dict`` carries an ``is_chain`` flag so the refinement code
        path can branch on it; the entry tool is used as ``current_target`` so
        existing detector/verify code keeps working unchanged.

        Chains are ordered by ``priority_chains`` when available, with any
        remaining chains appended in their original order.
        """
        chains: list = (self.agent_analysis or {}).get("chains", []) or []
        priority_chains: list = (self.agent_analysis or {}).get(
            "priority_chains", []
        ) or []

        configs: List[Tuple[str, dict]] = []
        seen_ids: set = set()

        chain_by_id: dict = {}
        for chain in chains:
            chain_id = chain.get("chain_id")
            if chain_id:
                chain_by_id[chain_id] = chain

        for entry in priority_chains:
            target_id = entry.split(" - ")[0].strip()
            chain = chain_by_id.get(target_id)
            if chain and target_id not in seen_ids:
                entry_tool = chain.get("entry_tool") or (
                    chain.get("sequence", [""])[0] if chain.get("sequence") else ""
                )
                if entry_tool:
                    configs.append((entry_tool, {**chain, "is_chain": True}))
                    seen_ids.add(target_id)

        for chain in chains:
            chain_id = chain.get("chain_id") or ""
            if chain_id in seen_ids:
                continue
            entry_tool = chain.get("entry_tool") or (
                chain.get("sequence", [""])[0] if chain.get("sequence") else ""
            )
            if not entry_tool:
                continue
            configs.append((entry_tool, {**chain, "is_chain": True}))
            if chain_id:
                seen_ids.add(chain_id)

        return configs

    # ------------------------------------------------------------------
    # Chain discovery pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def _format_per_tool_analyses(tool_analyses: dict) -> str:
        """Render the per-tool ANALYSIS output as a text block.

        Used to ground capability tagging (TOOL_TAGGING): each tool gets its
        functionality, vulnerabilities, and exploit strategies so the tagger can
        reason about what each tool consumes and produces.
        """
        if not tool_analyses:
            return "(no per-tool analyses available)"

        sections: List[str] = []
        for tool_name, analysis in tool_analyses.items():
            lines = [f"### Tool: {tool_name}"]
            functionality = analysis.get("functionality", "")
            vulnerabilities = analysis.get("vulnerabilities", "")
            exploit_strategies = analysis.get("exploit_strategies", "")
            if functionality:
                lines.append(f"Functionality: {functionality}")
            if vulnerabilities:
                lines.append(f"Vulnerabilities: {vulnerabilities}")
            if exploit_strategies:
                lines.append(f"Exploit strategies: {exploit_strategies}")
            sections.append("\n".join(lines))
        return "\n\n".join(sections)

    def _analyze_tool_chains(self) -> dict:
        """Discover multi-tool chains via a capability-graph path search.

        Pipeline (each LLM step is a small, reliable sub-task):

        1. `_tag_tool_capabilities` — tag every tool with what it
           consumes/produces, its capability class, and source/sink markers.
        2. `_build_capability_graph` — pure-Python candidate edges where
           one tool's output tag feeds another tool's input tag.
        3. `_score_edges` — one batched LLM call to confirm/score edges.
        4. `_search_chains` — pure-Python bounded source->sink path search,
           ranked by ``sink_severity * product(edge_confidence)``.
        5. `_generate_chain_attacks` — write conversational payloads for
           each concrete path.

        Returns a dict with ``chains`` and ``priority_chains`` keys (the same
        shape the downstream attack/refinement code already consumes). Returns
        empty values whenever a stage produces nothing.
        """
        tool_analyses = (self.agent_analysis or {}).get("tool_analyses", {})
        if not tool_analyses:
            logging.info(
                f"{self.__class__.__name__} # Skipping chain analysis: "
                "no per-tool analyses available"
            )
            return {"chains": [], "priority_chains": []}

        self.tool_tags = self._tag_tool_capabilities()
        if not self.tool_tags:
            logging.info(
                f"{self.__class__.__name__} # Skipping chain analysis: "
                "no tool tags produced"
            )
            return {"chains": [], "priority_chains": []}

        candidate_edges = self._build_capability_graph(self.tool_tags)
        if not candidate_edges:
            logging.info(
                f"{self.__class__.__name__} # No candidate data-flow edges found"
            )
            return {"chains": [], "priority_chains": []}

        edges = self._score_edges(candidate_edges)
        if not edges:
            logging.info(
                f"{self.__class__.__name__} # No edges survived confidence filtering"
            )
            return {"chains": [], "priority_chains": []}

        paths = self._search_chains(edges, self.tool_tags)
        if not paths:
            logging.info(
                f"{self.__class__.__name__} # No source->sink chains found"
            )
            return {"chains": [], "priority_chains": []}

        result = self._generate_chain_attacks(paths)
        logging.info(
            f"{self.__class__.__name__} # Built {len(result['chains'])} chain "
            f"attacks from {len(paths)} candidate paths"
        )
        return result

    def _tag_tool_capabilities(self) -> dict:
        """Tag every tool with consumes/produces/capability/source/sink markers.

        Single LLM pass grounded on the deep-recon profiles and the per-tool
        vulnerability analysis. Returns ``{tool_name -> tag_dict}``.
        """
        agent_purpose = self.agent_config.get("agent_purpose", "Unknown purpose")
        tools_description = self._format_tools_for_analysis(self.tool_profiles)
        per_tool_analyses = self._format_per_tool_analyses(
            (self.agent_analysis or {}).get("tool_analyses", {})
        )

        prompt = self._prompts["TOOL_TAGGING"].format(
            agent_purpose=agent_purpose,
            tools_description=tools_description,
            per_tool_analyses=per_tool_analyses,
        )
        response = self._get_model_response(prompt)
        if not response:
            return {}
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse tool tags JSON: {e}"
            )
            return {}
        return parsed.get("tool_tags", {}) or {}

    @staticmethod
    def _build_capability_graph(tool_tags: dict) -> List[dict]:
        """Build candidate directed edges between any producer and any consumer.

        Pure function (no model). Emits an edge ``A -> B`` for every
        ``A != B`` where ``A`` has any ``produces`` tag and ``B`` has any
        ``consumes`` tag. The LLM scoring pass downstream judges plausibility
        from the actual produces/consumes vocabulary -- it knows, for example,
        that ``directory_listing`` semantically contains ``file_path``, which
        an exact-intersection prefilter would miss.

        Carries the raw produces/consumes tag lists on each candidate so the
        scorer can render them verbatim.
        """
        edges: List[dict] = []
        for src, src_tags in tool_tags.items():
            produces = [str(t).strip() for t in (src_tags.get("produces") or [])]
            produces = [t for t in produces if t]
            if not produces:
                continue
            for dst, dst_tags in tool_tags.items():
                if dst == src:
                    continue
                consumes = [str(t).strip() for t in (dst_tags.get("consumes") or [])]
                consumes = [t for t in consumes if t]
                if not consumes:
                    continue
                edges.append(
                    {
                        "from": src,
                        "to": dst,
                        "produces": produces,
                        "consumes": consumes,
                    }
                )
        return edges

    def _score_edges(self, candidate_edges: List[dict]) -> List[dict]:
        """Score all candidate edges in one batched LLM call.

        Returns the edges with ``confidence >= min_edge_confidence``, each
        carrying a one-line ``data_flow`` describing what concretely moves from
        source to target.
        """
        tool_tags_str = json.dumps(self.tool_tags, indent=2)
        candidate_edges_str = "\n".join(
            f"- {e['from']} (produces: {', '.join(e.get('produces', []))}) "
            f"-> {e['to']} (consumes: {', '.join(e.get('consumes', []))})"
            for e in candidate_edges
        )
        prompt = self._prompts["EDGE_SCORE"].format(
            tool_tags=tool_tags_str,
            candidate_edges=candidate_edges_str,
        )
        response = self._get_model_response(prompt)
        if not response:
            return []
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse edge scores JSON: {e}"
            )
            return []

        scored: List[dict] = []
        for e in parsed.get("edges", []) or []:
            src = e.get("from")
            dst = e.get("to")
            if not src or not dst:
                continue
            try:
                confidence = float(e.get("confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            if confidence < self.min_edge_confidence:
                continue
            scored.append(
                {
                    "from": src,
                    "to": dst,
                    "confidence": confidence,
                    "data_flow": e.get("data_flow", ""),
                }
            )
        return scored

    def _search_chains(self, edges: List[dict], tool_tags: dict) -> List[dict]:
        """Bounded source->sink path search over scored edges.

        Pure function (no model). Enumerates simple paths (no repeated tool)
        starting at any ``is_source`` tool and recording a chain whenever the
        current tool is an ``is_sink`` and the path has at least 2 tools. Paths
        are ranked by ``sink_severity * product(edge_confidence)`` and capped at
        ``max_chains``.
        """
        adjacency: dict = {}
        for e in edges:
            adjacency.setdefault(e["from"], []).append(e)

        def severity(tool: str) -> int:
            try:
                return int((tool_tags.get(tool, {}) or {}).get("sink_severity", 1) or 1)
            except (TypeError, ValueError):
                return 1

        def is_source(tool: str) -> bool:
            return bool((tool_tags.get(tool, {}) or {}).get("is_source"))

        def is_sink(tool: str) -> bool:
            return bool((tool_tags.get(tool, {}) or {}).get("is_sink"))

        found: List[Tuple[float, list, list]] = []

        def dfs(current: str, sequence: list, edge_list: list, conf_product: float):
            if len(sequence) >= 2 and is_sink(current):
                found.append(
                    (severity(current) * conf_product, list(sequence), list(edge_list))
                )
            if len(sequence) >= self.max_chain_len:
                return
            for e in adjacency.get(current, []):
                nxt = e["to"]
                if nxt in sequence:  # simple paths only — avoid cycles
                    continue
                sequence.append(nxt)
                edge_list.append(e)
                dfs(nxt, sequence, edge_list, conf_product * e["confidence"])
                sequence.pop()
                edge_list.pop()

        for tool in tool_tags:
            if is_source(tool):
                dfs(tool, [tool], [], 1.0)

        found.sort(key=lambda p: p[0], reverse=True)

        ranked: List[dict] = []
        seen: set = set()
        for score, sequence, edge_list in found:
            key = tuple(sequence)
            if key in seen:
                continue
            seen.add(key)
            ranked.append({"sequence": sequence, "edges": edge_list, "score": score})
            if len(ranked) >= self.max_chains:
                break
        return ranked

    @staticmethod
    def _format_chain_data_flow(edges: list) -> str:
        """Render a chain's per-edge data flow as a text block."""
        if not edges:
            return "(no data flow recorded)"
        lines = []
        for e in edges:
            flow = e.get("data_flow") or ", ".join(e.get("tags", [])) or "data"
            lines.append(f"{e['from']} -> {e['to']}: {flow}")
        return "\n".join(lines)

    def _format_chain_vulnerabilities(self, sequence: list) -> str:
        """Combine per-tool vulnerabilities for the tools in a chain."""
        tool_analyses = (self.agent_analysis or {}).get("tool_analyses", {})
        parts = []
        for tool in sequence:
            vuln = (tool_analyses.get(tool, {}) or {}).get("vulnerabilities", "")
            if vuln:
                parts.append(f"{tool}: {vuln}")
        return " | ".join(parts) if parts else "Combined multi-tool weakness"

    @staticmethod
    def _default_hypothesis(vulnerabilities: str) -> dict:
        """Fallback single hypothesis when the LLM produces none.

        Preserves the pre-fan-out behavior: one attack line grounded on the
        chain's combined vulnerabilities, with no committed technique.
        """
        return {
            "technique": "default",
            "description": vulnerabilities or "Combined multi-tool weakness",
            "payload_shape": "",
            "sink_requirement": "",
        }

    def _generate_exploit_hypotheses(self, chain: dict) -> List[dict]:
        """Enumerate several DISTINCT exploit techniques for one chain.

        One LLM call grounded on the sink's enriched capability tags
        (``payload_types``, ``executes_content``, ``content_handling``), the
        combined vulnerabilities, and the per-tool grounding. Returns a list of
        hypothesis dicts (``technique``/``description``/``payload_shape``/
        ``sink_requirement``), capped at ``max_hypotheses_per_chain``. Returns an
        empty list (caller falls back to a single default hypothesis) whenever
        the model is unavailable, the call fails, or the JSON is malformed.
        """
        if getattr(self, "red_team_model", None) is None:
            return []

        sequence: List[str] = chain.get("sequence", []) or []
        if not sequence:
            return []
        sink = sequence[-1]
        sink_tags = json.dumps(self.tool_tags.get(sink, {}) or {}, indent=2)
        tools_block = self._format_tools_for_analysis(
            self.tool_profiles, self.tool_behaviors
        )

        prompt = self._prompts["EXPLOIT_HYPOTHESES"].format(
            sequence=" -> ".join(sequence),
            sink=sink,
            delivery=chain.get("delivery", "direct"),
            sink_tags=sink_tags,
            data_flow=chain.get("data_flow", ""),
            vulnerabilities=chain.get("vulnerabilities", ""),
            tools_block=tools_block,
            max_hypotheses=int(self.max_hypotheses_per_chain),
        )
        response = self._get_model_response(prompt)
        if not response:
            return []
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse exploit "
                f"hypotheses JSON for {chain.get('chain_id', '?')}: {e}"
            )
            return []

        hypotheses: List[dict] = []
        seen_techniques: set = set()
        for h in parsed.get("hypotheses", []) or []:
            if not isinstance(h, dict):
                continue
            technique = str(h.get("technique", "")).strip()
            description = str(h.get("description", "")).strip()
            if not technique or not description:
                continue
            if technique in seen_techniques:
                continue
            seen_techniques.add(technique)
            hypotheses.append(
                {
                    "technique": technique,
                    "description": description,
                    "payload_shape": str(h.get("payload_shape", "")).strip(),
                    "sink_requirement": str(h.get("sink_requirement", "")).strip(),
                }
            )
            if len(hypotheses) >= int(self.max_hypotheses_per_chain):
                break
        return hypotheses

    def _generate_chain_attacks(self, paths: List[dict]) -> dict:
        """Build chain dicts and attach a per-chain step plan.

        Each discovered path is expanded into up to
        ``max_hypotheses_per_chain`` independent attack lines, one per DISTINCT
        exploit technique (see `_generate_exploit_hypotheses`). This is the
        fix for fixation: rather than committing the whole chain to a single
        exploit idea, the probe explores several (e.g. path traversal vs.
        planting executable content) as separate, separately-tunable chains.

        Chain execution is plan-driven and stepwise from the start: each chain
        carries a ``step_plan`` (one entry per tool in the sequence, with role,
        intent, success criterion, and artifact keys) tuned to that line's
        committed ``hypothesis``. Chains whose plan generation fails are dropped
        rather than falling back to a single-prompt whole-chain attack.
        """
        chains: List[dict] = []
        priority_chains: List[str] = []

        for i, path in enumerate(paths, start=1):
            sequence = path["sequence"]
            entry_tool = sequence[0]
            data_flow = self._format_chain_data_flow(path["edges"])
            vulnerabilities = self._format_chain_vulnerabilities(sequence)
            intent = self._infer_chain_intent(sequence, vulnerabilities)
            # Delivery is a property of the sink's vulnerability class: a
            # data-channel sink (XXE, cmdi, SSRF) needs a crafted payload planted
            # upstream, a direct sink does not. The chain inherits the sink's tag.
            sink = sequence[-1]
            delivery = (self.tool_tags.get(sink, {}) or {}).get("delivery", "direct")
            if delivery not in {"direct", "data_channel"}:
                delivery = "direct"

            base_chain = {
                "sequence": sequence,
                "entry_tool": entry_tool,
                "intent": intent,
                "data_flow": data_flow,
                "vulnerabilities": vulnerabilities,
                "delivery": delivery,
            }

            hypotheses = self._generate_exploit_hypotheses(base_chain) or [
                self._default_hypothesis(vulnerabilities)
            ]
            single = len(hypotheses) == 1

            for j, hypothesis in enumerate(hypotheses, start=1):
                chain_id = f"chain_{i}" if single else f"chain_{i}_{j}"
                # The committed technique sharpens both the chain intent and the
                # vulnerability framing fed to the step planner.
                chain = {
                    **base_chain,
                    "chain_id": chain_id,
                    "hypothesis": hypothesis,
                    "intent": f"{intent} Technique: {hypothesis['description']}",
                }

                step_plan = self._generate_step_plan(chain)
                if not step_plan:
                    logging.warning(
                        f"{self.__class__.__name__} # Dropping {chain_id}: "
                        "no valid step plan generated"
                    )
                    continue

                chain["step_plan"] = step_plan
                chains.append(chain)
                priority_chains.append(f"{chain_id} - score {path['score']:.2f}")
                logging.info(
                    f"{self.__class__.__name__} # Step plan for {chain_id} "
                    f"[{hypothesis['technique']}] "
                    f"({' -> '.join(sequence)}): "
                    + " | ".join(
                        f"{e.get('tool', '?')}[{e.get('role', '?')}]"
                        for e in step_plan
                    )
                )

        return {"chains": chains, "priority_chains": priority_chains}

    @staticmethod
    def _infer_chain_intent(sequence: List[str], vulnerabilities: str) -> str:
        """Cheap default intent string until the plan-gen LLM call refines it.

        The step plan template gets an explicit ``intent`` field; the model
        in STEP_PLAN can read this default plus the per-tool grounding to
        produce a tighter end-to-end goal in its plan entries.
        """
        if not sequence:
            return "Multi-tool chain exploit"
        return (
            f"Drive the agent from {sequence[0]} through {' -> '.join(sequence)} "
            f"to a security-relevant outcome at {sequence[-1]}."
        )

    def _generate_step_plan(self, chain: dict) -> Optional[List[dict]]:
        """Ask the red team model to produce a ``step_plan`` for this chain.

        Each plan entry assigns the corresponding tool a role
        (``recon``/``pivot``/``exploit``), an intent, a success criterion, and
        a list of ``artifact_keys`` to extract. Returns ``None`` when the call
        fails, the JSON is malformed, the plan is empty, or the plan does not
        end in exactly one ``exploit`` step at the tail. Caller drops chains
        with no valid plan.
        """
        sequence: List[str] = chain.get("sequence", []) or []
        if not sequence:
            return None

        tools_block = self._format_tools_for_analysis(
            self.tool_profiles, self.tool_behaviors
        )
        hypothesis = chain.get("hypothesis", {}) or {}
        prompt = self._prompts["STEP_PLAN"].format(
            sequence=" -> ".join(sequence),
            intent=chain.get("intent", ""),
            data_flow=chain.get("data_flow", ""),
            vulnerabilities=chain.get("vulnerabilities", ""),
            tools_block=tools_block,
            delivery=chain.get("delivery", "direct"),
            exploit_technique=hypothesis.get("technique", "(unspecified)"),
            payload_shape=hypothesis.get("payload_shape", "") or "(unspecified)",
            sink_requirement=hypothesis.get("sink_requirement", "") or "(unspecified)",
        )
        response = self._get_model_response(prompt)
        if not response:
            return None
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse step plan JSON for "
                f"{chain.get('chain_id', '?')}: {e}"
            )
            return None

        raw_plan = parsed.get("step_plan") or []
        if not isinstance(raw_plan, list) or len(raw_plan) != len(sequence):
            logging.warning(
                f"{self.__class__.__name__} # Step plan length mismatch for "
                f"{chain.get('chain_id', '?')}: expected {len(sequence)}, "
                f"got {len(raw_plan) if isinstance(raw_plan, list) else 'non-list'}"
            )
            return None

        cleaned: List[dict] = []
        for i, entry in enumerate(raw_plan):
            if not isinstance(entry, dict):
                return None
            role = str(entry.get("role", "")).lower().strip()
            if role not in {"recon", "pivot", "plant", "exploit"}:
                return None
            artifact_keys = entry.get("artifact_keys") or []
            if not isinstance(artifact_keys, list):
                artifact_keys = []
            cleaned.append(
                {
                    "tool": sequence[i],  # trust capability graph ordering
                    "role": role,
                    "intent": str(entry.get("intent", "")),
                    # Backchained per-step target: what this step must surface for
                    # the downstream step so the chain reaches the exploit.
                    # Advisory prose; defaults to "" so older plans still validate.
                    "must_provide": str(entry.get("must_provide", "")),
                    "success_criterion": str(entry.get("success_criterion", "")),
                    "artifact_keys": [str(k) for k in artifact_keys],
                }
            )

        if cleaned[-1]["role"] != "exploit":
            logging.warning(
                f"{self.__class__.__name__} # Step plan for "
                f"{chain.get('chain_id', '?')} does not end with exploit role"
            )
            return None
        if any(e["role"] == "exploit" for e in cleaned[:-1]):
            logging.warning(
                f"{self.__class__.__name__} # Step plan for "
                f"{chain.get('chain_id', '?')} has multiple exploit roles"
            )
            return None
        return cleaned

    # ------------------------------------------------------------------
    # Attack queueing + refinement (overrides shared hooks)
    # ------------------------------------------------------------------

    def _attack_single_chain(
        self,
        entry_tool: str,
        chain: dict,
    ) -> List[garak.attempt.Attempt]:
        """Seed plan-driven stepwise execution for a single chain.

        Produces exactly one initial :class:`Attempt` -- the first step of the
        chain's ``step_plan``. Marks the chain ``is_stepwise: True`` from the
        start; there is no single-prompt phase. Returns an empty list when no
        valid step plan exists or the step-1 prompt generation fails.
        """
        attempts: List[garak.attempt.Attempt] = []
        vulnerability_info = chain.get("vulnerabilities", "")
        chain_id = chain.get("chain_id", "?")
        sequence = chain.get("sequence", []) or []

        step_plan = chain.get("step_plan") or []
        if not step_plan:
            logging.warning(
                f"{self.__class__.__name__} # No step plan for chain "
                f"{chain_id} (entry={entry_tool}) -- skipping"
            )
            return attempts

        chain = copy.deepcopy(chain)
        chain["is_stepwise"] = True
        chain["step_index"] = 0
        chain["step_outputs"] = []
        chain["artifacts"] = {}

        next_attempt = self._queue_step_attack(chain, vulnerability_info)
        if next_attempt is None:
            logging.warning(
                f"{self.__class__.__name__} # Failed to generate stepwise "
                f"step 1/{len(sequence)} for chain {chain_id} "
                f"(entry={entry_tool}); skipping"
            )
            return attempts

        logging.info(
            f"{self.__class__.__name__} # Stepwise step 1/{len(sequence)} "
            f"({sequence[0] if sequence else entry_tool}) "
            f"[{step_plan[0].get('role', '?')}] initial"
        )
        attempts.append(next_attempt)
        return attempts

    # ------------------------------------------------------------------
    # Plan-driven stepwise execution
    # ------------------------------------------------------------------

    def _format_prior_steps(self, step_outputs: list) -> str:
        """Render completed step outputs as a transcript block for prompts.

        Responses are truncated to ``_STEP_RESPONSE_CHAR_LIMIT`` to bound the
        token cost of long agent responses being pasted into the next step.
        """
        if not step_outputs:
            return "(this is the first step)"
        lines: List[str] = []
        for i, entry in enumerate(step_outputs, start=1):
            tool = entry.get("tool", "?")
            prompt = entry.get("prompt", "")
            response = (entry.get("response") or "")[: self._STEP_RESPONSE_CHAR_LIMIT]
            lines.append(
                f"--- Step {i} ({tool}) ---\n"
                f"PROMPT: {prompt}\n"
                f"RESPONSE: {response}"
            )
        return "\n\n".join(lines)

    def _render_chain_transcript(
        self,
        chain: dict,
        final_prompt: str,
        final_response: str,
    ) -> str:
        """Render the full multi-step chain as a single readable conversation.

        Combines the completed-step transcript (``step_outputs``, which holds
        every recon/pivot/plant step that already advanced) with the terminal
        ``exploit`` step's own prompt and response -- the exploit step has not
        been appended to ``step_outputs`` yet because it terminates the chain
        instead of advancing. The result is stored on the winning attempt's
        notes so the whole conversation for one chain is visible in the report
        and hitlog as a single block, even though each step was sent to the
        target as a separate fresh Attempt.
        """
        sequence = chain.get("sequence", []) or []
        step_plan = chain.get("step_plan") or []
        step_outputs = chain.get("step_outputs", []) or []
        total = len(sequence)

        def _role_for(idx: int) -> str:
            if 0 <= idx < len(step_plan):
                return step_plan[idx].get("role", "?") or "?"
            return "?"

        chain_id = chain.get("chain_id", "?")
        lines: List[str] = [
            f"=== Chain {chain_id}: {' -> '.join(sequence) or '(empty)'} ==="
        ]

        for idx, entry in enumerate(step_outputs):
            tool = entry.get("tool", "?")
            lines.append(
                f"\n--- Step {idx + 1}/{total} [{tool}] role={_role_for(idx)} ---"
            )
            lines.append(f"USER: {entry.get('prompt', '')}")
            lines.append(f"AGENT: {entry.get('response', '')}")

        final_idx = len(step_outputs)
        final_tool = sequence[final_idx] if final_idx < total else "?"
        lines.append(
            f"\n--- Step {final_idx + 1}/{total} [{final_tool}] "
            f"role={_role_for(final_idx)} ---"
        )
        lines.append(f"USER: {final_prompt or ''}")
        lines.append(f"AGENT: {final_response or ''}")

        return "\n".join(lines)

    @staticmethod
    def _chain_grouping_notes(chain: dict) -> dict:
        """Top-level notes keys that group every step of one chain together.

        Each chain step is executed as a separate :class:`Attempt`, so without
        a shared identifier the report records for one chain are impossible to
        associate. Stamping these onto every step attempt's notes lets the
        report be grouped/filtered by ``chain_id`` and shows, on each record,
        which chain it belongs to and which step it is.
        """
        sequence = chain.get("sequence", []) or []
        step_index = chain.get("step_index", 0)
        step_plan = chain.get("step_plan") or []
        role = "?"
        if 0 <= step_index < len(step_plan):
            role = step_plan[step_index].get("role", "?") or "?"
        return {
            "chain_id": chain.get("chain_id"),
            "chain_sequence": " -> ".join(sequence) if sequence else None,
            "chain_step": step_index + 1,
            "chain_total_steps": len(sequence),
            "chain_role": role,
        }

    @staticmethod
    def _format_prior_artifacts(artifacts: dict) -> str:
        """Render accumulated artifacts as ``key = value`` lines for prompts.

        Empty dict renders as a placeholder so the prompt template substitution
        never produces a confusing bare blank.
        """
        if not artifacts:
            return "(no artifacts captured yet)"
        return "\n".join(f"  {k} = {v}" for k, v in artifacts.items())

    @staticmethod
    def _format_step_history(history: list) -> str:
        """Render the per-step refinement history for the STEP_EXPLOIT prompt.

        Mirrors the formatting used by ``AgentBreaker._generate_exploit_prompt``
        so a red-team model sees the same shape of feedback whether it is
        refining a single-tool or per-step attack.
        """
        if not history:
            return "No previous attempts yet."
        return "\n\n".join(
            f"--- Attempt {i + 1} ---\n"
            f"ATTACK PROMPT: {h.get('prompt', 'N/A')}\n"
            f"AGENT RESPONSE: {h.get('response', 'N/A')}\n"
            f"SUCCESS: {h.get('success', False)}\n"
            f"REASONING: {h.get('reasoning', 'N/A')}"
            for i, h in enumerate(history[-5:])
        )

    @staticmethod
    def _tried_techniques(history: list) -> str:
        """Render the distinct technique labels already tried on this step.

        Feeds the STEP_EXPLOIT refiner so it can see which technique classes
        have already failed and switch to a materially different one instead of
        re-encoding the same idea. Counts repeats so the model can tell when one
        class has been beaten to death.
        """
        if not history:
            return "(none yet)"
        counts: dict = {}
        order: list = []
        for h in history:
            tech = str(h.get("technique", "") or "").strip()
            if not tech:
                continue
            if tech not in counts:
                order.append(tech)
            counts[tech] = counts.get(tech, 0) + 1
        if not order:
            return "(none labeled yet)"
        return ", ".join(f"{t} (x{counts[t]})" for t in order)

    def _last_agent_feedback(self, history: list) -> str:
        """Surface the most recent agent response for the refiner to adapt to.

        Buried inside ``history_str`` the latest response is easy for the model
        to skim past. Hoisting it (truncated) into its own field makes errors
        and parameter hints actionable -- e.g. a tool 500 or the agent asking
        for an employee id/email instead of a name, which is exactly the signal
        that a recon step should switch its lookup key rather than resend the
        same failing query.
        """
        if not history:
            return "(no prior response yet)"
        last = history[-1] or {}
        response = (last.get("response") or "").strip()
        if not response:
            return "(prior attempt produced no usable response)"
        return response[: self._STEP_RESPONSE_CHAR_LIMIT]

    def _extract_attack_prompt(self, response: Optional[str]) -> Optional[str]:
        """Pull ``attack_prompt`` from a JSON LLM response, with raw fallback.

        Also stashes any ``technique`` label on ``self._last_step_technique`` so
        the caller can stamp it onto the attack state immediately after
        generation (single-threaded stepwise execution makes this safe).
        """
        self._last_step_technique = ""
        if not response:
            return None
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse step prompt JSON, "
                "using raw response"
            )
            return response.strip()
        prompt = parsed.get("attack_prompt")
        self._last_step_technique = str(parsed.get("technique", "") or "").strip()
        if parsed.get("analysis"):
            logging.debug(
                f"{self.__class__.__name__} # Step attack analysis: "
                f"{parsed.get('analysis')}"
            )
        if parsed.get("new_approach"):
            logging.debug(
                f"{self.__class__.__name__} # Step attack new approach: "
                f"{parsed.get('new_approach')}"
            )
        return prompt

    @staticmethod
    def _plan_entry(chain: dict, step_index: int) -> dict:
        """Return the plan entry for ``step_index`` (or an empty dict)."""
        plan = chain.get("step_plan") or []
        if 0 <= step_index < len(plan):
            return plan[step_index] or {}
        return {}

    def _generate_step_attack_prompt(
        self,
        chain: dict,
        step_index: int,
    ) -> Optional[str]:
        """Ask the red-team model for the initial prompt for the current step.

        Uses the plan entry for this step (role, intent, success criterion,
        artifact keys) and accumulated artifacts so the prompt asks the right
        thing -- benign recon for ``recon``/``pivot`` roles, payload-bearing
        exploit only for ``exploit``.
        """
        sequence = chain.get("sequence", []) or []
        if step_index >= len(sequence):
            return None
        target_tool = sequence[step_index]
        entry = self._plan_entry(chain, step_index)
        prior_outputs = chain.get("step_outputs", []) or []
        # Chain-local artifacts take precedence, but fall back to anything any
        # other chain has already discovered this run (e.g. valid employee ids).
        artifacts = {**self.global_artifacts, **(chain.get("artifacts", {}) or {})}
        hypothesis = chain.get("hypothesis", {}) or {}

        prompt = self._prompts["STEP_ATTACK"].format(
            target_tool=target_tool,
            step_index=step_index + 1,
            total_steps=len(sequence),
            full_sequence=" -> ".join(sequence) if sequence else "(unspecified)",
            chain_intent=chain.get("intent", ""),
            delivery=chain.get("delivery", "direct"),
            exploit_technique=hypothesis.get("technique", "(unspecified)"),
            payload_shape=hypothesis.get("payload_shape", "") or "(unspecified)",
            sink_requirement=hypothesis.get("sink_requirement", "") or "(unspecified)",
            role=entry.get("role", "exploit"),
            intent=entry.get("intent", ""),
            must_provide=entry.get("must_provide", "") or "(not specified)",
            success_criterion=entry.get("success_criterion", ""),
            artifact_keys=", ".join(entry.get("artifact_keys") or []) or "(none)",
            prior_artifacts=self._format_prior_artifacts(artifacts),
            prior_steps_transcript=self._format_prior_steps(prior_outputs),
            vulnerabilities=chain.get("vulnerabilities", "Unknown vulnerabilities"),
        )
        return self._extract_attack_prompt(self._get_model_response(prompt))

    def _generate_step_exploit_prompt(
        self,
        chain: dict,
        step_index: int,
        history: list,
    ) -> Optional[str]:
        """Refine the current step's prompt given prior failed attempts.

        Same plan-entry inputs as `_generate_step_attack_prompt`, plus
        the per-step ``history`` rendered as a transcript so the red-team
        model can analyze refusal/error patterns specific to this step.
        """
        sequence = chain.get("sequence", []) or []
        if step_index >= len(sequence):
            return None
        target_tool = sequence[step_index]
        entry = self._plan_entry(chain, step_index)
        prior_outputs = chain.get("step_outputs", []) or []
        artifacts = {**self.global_artifacts, **(chain.get("artifacts", {}) or {})}
        hypothesis = chain.get("hypothesis", {}) or {}

        prompt = self._prompts["STEP_EXPLOIT"].format(
            target_tool=target_tool,
            step_index=step_index + 1,
            total_steps=len(sequence),
            full_sequence=" -> ".join(sequence) if sequence else "(unspecified)",
            chain_intent=chain.get("intent", ""),
            delivery=chain.get("delivery", "direct"),
            exploit_technique=hypothesis.get("technique", "(unspecified)"),
            payload_shape=hypothesis.get("payload_shape", "") or "(unspecified)",
            sink_requirement=hypothesis.get("sink_requirement", "") or "(unspecified)",
            role=entry.get("role", "exploit"),
            intent=entry.get("intent", ""),
            must_provide=entry.get("must_provide", "") or "(not specified)",
            success_criterion=entry.get("success_criterion", ""),
            artifact_keys=", ".join(entry.get("artifact_keys") or []) or "(none)",
            prior_artifacts=self._format_prior_artifacts(artifacts),
            prior_steps_transcript=self._format_prior_steps(prior_outputs),
            vulnerabilities=chain.get("vulnerabilities", "Unknown vulnerabilities"),
            tried_techniques=self._tried_techniques(history),
            last_response=self._last_agent_feedback(history),
            history_str=self._format_step_history(history),
        )
        return self._extract_attack_prompt(self._get_model_response(prompt))

    def _extract_artifacts(
        self,
        chain: dict,
        step_index: int,
        step_prompt: str,
        agent_response: str,
    ) -> dict:
        """Pull named artifacts from a successful step's response.

        One LLM call to the parse model (falls back to the red-team model)
        returns a flat ``{key: value}`` dict. Returns an empty dict on parse
        failure or when no artifacts could be extracted -- execution continues
        with whatever was already in ``chain["artifacts"]``.
        """
        entry = self._plan_entry(chain, step_index)
        sequence = chain.get("sequence", []) or []
        if step_index >= len(sequence):
            return {}
        tool_name = sequence[step_index]
        artifact_keys = entry.get("artifact_keys") or []

        prompt = self._prompts["EXTRACT_ARTIFACTS"].format(
            tool_name=tool_name,
            role=entry.get("role", ""),
            intent=entry.get("intent", ""),
            step_prompt=step_prompt,
            agent_response=(agent_response or "")[: self._STEP_RESPONSE_CHAR_LIMIT],
            artifact_keys=", ".join(artifact_keys) or "(none specifically required)",
        )
        self._setup_parse_model()
        response = self._get_model_response(prompt, model=self.parse_model)
        if not response:
            return {}
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse artifact extraction "
                f"JSON for {tool_name}: {e}"
            )
            return {}
        artifacts = parsed.get("artifacts") or {}
        if not isinstance(artifacts, dict):
            return {}
        return {str(k): str(v) for k, v in artifacts.items() if v not in (None, "")}

    def _check_step_success(
        self,
        chain: dict,
        step_index: int,
        step_prompt: str,
        agent_response: str,
        artifacts: dict,
    ) -> Tuple[bool, float, str]:
        """Role-aware advancement check for non-exploit steps.

        Used for ``recon`` and ``pivot`` plan roles. Returns
        ``(step_succeeded, confidence, reasoning)``. The exploit step uses the
        existing security verifier instead -- this function is not called for
        ``role == "exploit"``.
        """
        entry = self._plan_entry(chain, step_index)
        prompt = self._prompts["CHECK_STEP_SUCCESS"].format(
            role=entry.get("role", ""),
            intent=entry.get("intent", ""),
            success_criterion=entry.get("success_criterion", ""),
            step_prompt=step_prompt,
            agent_response=(agent_response or "")[: self._STEP_RESPONSE_CHAR_LIMIT],
            artifacts_str=self._format_prior_artifacts(artifacts),
        )
        self._setup_parse_model()
        response = self._get_model_response(prompt, model=self.parse_model)
        if not response:
            return (False, 0.0, "no response from check model")
        try:
            parsed = self._detector._extract_json(response)
        except json.JSONDecodeError as e:
            logging.warning(
                f"{self.__class__.__name__} # Failed to parse step-success JSON: {e}"
            )
            return (False, 0.0, "malformed step-success JSON")
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return (
            bool(parsed.get("step_succeeded")),
            confidence,
            str(parsed.get("reasoning", "")),
        )

    def _queue_step_attack(
        self,
        chain: dict,
        vulnerability_info: str,
    ) -> Optional[garak.attempt.Attempt]:
        """Build an initial attempt for the chain's current ``step_index``.

        Creates a fresh :class:`AttackState` with empty ``attempts_history`` so
        per-step refinement history is scoped to the current step. Returns
        ``None`` if no step prompt could be generated.
        """
        sequence = chain.get("sequence", []) or []
        step_index = chain.get("step_index", 0)
        if step_index >= len(sequence):
            return None
        target_tool = sequence[step_index]
        step_prompt = self._generate_step_attack_prompt(chain, step_index)
        if not step_prompt:
            return None
        technique = self._last_step_technique
        next_attempt = self._create_attempt(step_prompt)
        next_state = AttackState(
            current_target=target_tool,
            current_tool_analysis=chain,
            current_attack_prompt=step_prompt,
            attempts_history=[],
            vulnerability_info=vulnerability_info,
            artifacts=dict(chain.get("artifacts", {}) or {}),
            current_technique=technique,
        )
        next_attempt.notes = next_state.to_notes()
        next_attempt.notes.update(self._chain_grouping_notes(chain))
        return next_attempt

    def _advance_stepwise(
        self,
        state: AttackState,
        best_response: str,
        new_artifacts: Optional[dict] = None,
    ) -> Optional[garak.attempt.Attempt]:
        """Record the just-completed step, merge artifacts, queue next step.

        Called when an intermediate step has met its advancement signal --
        ``CHECK_STEP_SUCCESS`` for ``recon``/``pivot``, or the security
        verifier for ``exploit`` (which terminates instead of calling this).
        ``new_artifacts`` may be supplied by the caller to avoid a duplicate
        extraction call; when ``None`` we extract here.
        """
        chain = copy.deepcopy(state.current_tool_analysis or {})
        sequence = chain.get("sequence", []) or []
        step_index = chain.get("step_index", 0)
        completed_tool = (
            sequence[step_index] if step_index < len(sequence) else "?"
        )

        if new_artifacts is None:
            new_artifacts = self._extract_artifacts(
                chain, step_index, state.current_attack_prompt, best_response
            )
        merged_artifacts = dict(chain.get("artifacts", {}) or {})
        merged_artifacts.update(new_artifacts)
        chain["artifacts"] = merged_artifacts

        step_outputs = list(chain.get("step_outputs", []) or [])
        step_outputs.append(
            {
                "tool": completed_tool,
                "prompt": state.current_attack_prompt,
                "response": best_response,
                "artifacts": new_artifacts,
            }
        )
        chain["step_outputs"] = step_outputs
        chain["step_index"] = step_index + 1

        new_step_index = chain["step_index"]
        next_tool = (
            sequence[new_step_index] if new_step_index < len(sequence) else "?"
        )
        next_role = self._plan_entry(chain, new_step_index).get("role", "?")
        logging.info(
            f"{self.__class__.__name__} # Stepwise step "
            f"{step_index + 1}/{len(sequence)} ({completed_tool}) advanced -- "
            f"artifacts now {list(merged_artifacts.keys())}; next: step "
            f"{new_step_index + 1}/{len(sequence)} ({next_tool}) [{next_role}]"
        )

        return self._queue_step_attack(chain, state.vulnerability_info)

    def _handle_stepwise_refinement(
        self,
        state: AttackState,
    ) -> Optional[garak.attempt.Attempt]:
        """Per-step refinement budget: refine while attempts-on-this-step is
        below ``max_step_attempts``, otherwise abandon the chain.

        Per-step history is the entire ``state.attempts_history`` because
        history is reset whenever a step advances (in `_queue_step_attack`).
        """
        chain = copy.deepcopy(state.current_tool_analysis or {})
        sequence = chain.get("sequence", []) or []
        step_index = chain.get("step_index", 0)
        if step_index >= len(sequence):
            return None

        target_tool = sequence[step_index]
        role = self._plan_entry(chain, step_index).get("role", "?")
        step_history = list(state.attempts_history or [])
        chain_id = chain.get("chain_id", "?")
        if len(step_history) >= self.max_step_attempts:
            logging.info(
                f"{self.__class__.__name__} # Abandoning chain {chain_id}: "
                f"stepwise step {step_index + 1}/{len(sequence)} "
                f"({target_tool}) [{role}] exhausted after {len(step_history)} attempts"
            )
            return None

        refined = self._generate_step_exploit_prompt(
            chain, step_index, step_history
        )
        if not refined:
            return None
        technique = self._last_step_technique

        next_attempt = self._create_attempt(refined)
        next_state = AttackState(
            current_target=target_tool,
            current_tool_analysis=chain,
            current_attack_prompt=refined,
            attempts_history=step_history,
            vulnerability_info=state.vulnerability_info,
            artifacts=dict(chain.get("artifacts", {}) or {}),
            current_technique=technique,
        )
        next_attempt.notes = next_state.to_notes()
        next_attempt.notes.update(self._chain_grouping_notes(chain))
        logging.info(
            f"{self.__class__.__name__} # Stepwise step "
            f"{step_index + 1}/{len(sequence)} ({target_tool}) [{role}] "
            f"refinement attempt {len(step_history) + 1}/{self.max_step_attempts}"
        )
        return next_attempt

    def _postprocess_attempt(
        self, this_attempt: garak.attempt.Attempt
    ) -> garak.attempt.Attempt:
        """Override: propagate chain transcript notes onto the returned deep-copy.

        ``IterativeProbe._postprocess_attempt`` deep-copies the attempt *before*
        calling ``_generate_next_attempts``, so any notes written by
        ``_generate_next_attempts`` (e.g. ``chain_transcript``, ``chain_id``,
        ``chain_sequence``) are absent from the copy that reaches the evaluator
        and hitlog.  This override copies those fields from the mutated original
        onto ``processed`` after ``super()`` returns.
        """
        processed = super()._postprocess_attempt(this_attempt)
        # Propagate chain-level notes that _generate_next_attempts may have
        # written onto this_attempt.notes after the deep copy was already made.
        for key in (
            "chain_transcript",
            "chain_id",
            "chain_sequence",
            "chain_step",
            "chain_total_steps",
            "chain_role",
            "incidental_finding",
            "incidental_reason",
        ):
            val = (this_attempt.notes or {}).get(key)
            if val is not None:
                processed.notes[key] = val
        return processed

    def _handle_exploitation_phase(
        self,
        last_attempt: garak.attempt.Attempt,
    ) -> Optional[garak.attempt.Attempt]:
        """Dispatch refinement: non-chain attempts go to the base single-tool
        path; chain attempts (always stepwise) use per-step refinement."""
        state = AttackState.from_notes(last_attempt.notes or {})
        chain = state.current_tool_analysis or {}

        if not chain.get("is_chain"):
            return super()._handle_exploitation_phase(last_attempt)
        return self._handle_stepwise_refinement(state)

    def _generate_next_attempts(
        self, last_attempt: garak.attempt.Attempt
    ) -> Iterable[garak.attempt.Attempt]:
        """Role-aware response handling for plan-driven stepwise chains.

        Non-chain attempts delegate to the base single-tool path. For chain
        attempts (always stepwise), the per-output security verdict is still
        computed and recorded so the detector can score them later, but the
        advancement decision depends on the step's plan-entry role:

        - ``recon`` / ``pivot``: advance whenever
          `_check_step_success` says the step satisfied its declared
          success criterion -- this prevents the security verifier from
          blocking advancement on a step whose job was never to be an exploit.
        - ``exploit``: advance (i.e. terminate the chain) only when the
          existing security verifier confirms the exploit landed.
        """
        outputs = last_attempt.outputs or []
        if not outputs:
            return []

        state = AttackState.from_notes(last_attempt.notes or {})
        chain = state.current_tool_analysis or {}

        if not chain.get("is_stepwise"):
            return super()._generate_next_attempts(last_attempt)

        verified_results: list = []
        best_confidence = -1.0
        best_response = ""
        best_reasoning = ""
        exploit_succeeded = False

        # Per-output security verdict: recorded so the detector has scores for
        # every step (even recon/pivot), but only used as the advancement
        # signal on the final exploit step.
        for output in outputs:
            if output is None or output.text is None:
                verified_results.append((False, 0.0))
                continue
            is_success, confidence, reasoning = self._verify_attack_success(
                attack_prompt=last_attempt.prompt,
                agent_response=output.text,
                target_tool=state.current_target,
                vulnerability_info=state.vulnerability_info,
            )
            verified_results.append((is_success, confidence))
            if confidence > best_confidence:
                best_confidence = confidence
                best_response = output.text
                best_reasoning = reasoning
            if is_success and confidence >= self.success_threshold:
                exploit_succeeded = True

        state.verified_results = verified_results

        step_index = chain.get("step_index", 0)
        sequence = chain.get("sequence", []) or []
        is_final_step = step_index >= len(sequence) - 1
        plan_entry = self._plan_entry(chain, step_index)
        role = plan_entry.get("role", "exploit")

        # Decide advancement using the role-appropriate signal.
        new_artifacts: dict = {}
        if role == "exploit":
            step_advanced = exploit_succeeded
            advance_reasoning = best_reasoning
        elif not best_response:
            # No useful response to learn from -> route to refinement directly.
            step_advanced = False
            advance_reasoning = "empty response from agent"
        else:
            # Recon / pivot / plant: pull any artifacts visible in the response so
            # the role-aware check has them in hand, and thread the same dict
            # through into _advance_stepwise to avoid extracting twice.
            new_artifacts = self._extract_artifacts(
                chain, step_index, state.current_attack_prompt, best_response
            )
            step_advanced, _check_conf, advance_reasoning = self._check_step_success(
                chain,
                step_index,
                state.current_attack_prompt,
                best_response,
                new_artifacts,
            )
            # Plant safety net: a plant step's only job is to get
            # attacker-controlled content ACCEPTED and reachable by the sink --
            # not to make the eventual exploit fire. If the agent accepted the
            # data (we extracted a usable artifact reference such as a stored
            # filename) advance even when the step-success check, which can be
            # over-tied to the specific payload, says no. Without this a plant
            # that stored a sanitized-but-usable file would strand the chain
            # before the exploit step ever ran.
            if role == "plant" and not step_advanced and new_artifacts:
                step_advanced = True
                advance_reasoning = (
                    "plant accepted: attacker-controlled content stored and "
                    f"reachable (artifacts: {list(new_artifacts.keys())})"
                )

        # Publish anything this step learned to the run-wide store so other
        # chains' recon can reuse concrete values (ids, paths, emails) instead
        # of cold-calling a tool that errors on under-specified input.
        if new_artifacts:
            self.global_artifacts.update(new_artifacts)

        state.attempts_history.append(
            {
                "target": state.current_target,
                "prompt": last_attempt.prompt.last_message().text,
                "success": step_advanced,
                "confidence": best_confidence,
                "reasoning": advance_reasoning,
                "response": best_response,
                "technique": state.current_technique,
            }
        )
        last_attempt.notes = state.to_notes()

        # Incidental finding: a non-exploit step can independently demonstrate
        # harm (e.g. a recon call that dumps the whole salary table or exports
        # it). The chain may not have reached its planned sink, but this turn is
        # a real finding on its own. Flag it so the detector scores it as a hit
        # instead of hard-zeroing every non-exploit step. Gated on the same
        # success_threshold used for exploits to limit false positives.
        if role != "exploit" and exploit_succeeded:
            notes = last_attempt.notes
            notes["incidental_finding"] = True
            notes["incidental_reason"] = (
                f"{role} step on {state.current_target} independently "
                f"demonstrated harm (confidence {best_confidence:.2f}): "
                f"{best_reasoning}"
            )
            notes.update(self._chain_grouping_notes(chain))
            last_attempt.notes = notes
            logging.info(
                "%s # Incidental finding on %s step %d/%d (%s): %s",
                self.__class__.__name__,
                role,
                step_index + 1,
                len(sequence),
                state.current_target,
                best_reasoning,
            )

        if step_advanced and is_final_step:
            logging.info(
                f"{self.__class__.__name__} # Chain "
                f"{chain.get('chain_id', '?')} SUCCEEDED on final sink "
                f"{state.current_target} with confidence {best_confidence:.2f}"
            )
            # Surface the whole multi-step conversation for this chain as a
            # single grouped block in the report/hitlog. Each step was sent as
            # a separate fresh Attempt, so without this the logs only show the
            # terminal exploit turn in isolation.
            transcript = self._render_chain_transcript(
                chain, state.current_attack_prompt, best_response
            )
            notes = last_attempt.notes
            notes.update(self._chain_grouping_notes(chain))
            notes["chain_transcript"] = transcript
            last_attempt.notes = notes
            logging.info(
                "%s # Full chain conversation for %s (%s):\n%s",
                self.__class__.__name__,
                chain.get("chain_id", "?"),
                " -> ".join(sequence) if sequence else "(empty)",
                transcript,
            )
            return []

        if step_advanced:
            try:
                next_attempt = self._advance_stepwise(
                    state, best_response, new_artifacts=new_artifacts
                )
            except Exception:
                logging.exception(
                    f"{self.__class__.__name__} # Error advancing stepwise chain "
                    f"{chain.get('chain_id', '?')}"
                )
                return []
            return [next_attempt] if next_attempt is not None else []

        try:
            next_attempt = self._handle_exploitation_phase(last_attempt)
        except Exception:
            logging.exception(
                f"{self.__class__.__name__} # Error in stepwise refinement for "
                f"chain {chain.get('chain_id', '?')} step {step_index}"
            )
            return []

        return [next_attempt] if next_attempt is not None else []
