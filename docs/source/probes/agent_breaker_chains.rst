garak.probes.agent_breaker_chains
=================================

.. automodule:: garak.probes.agent_breaker_chains
   :members:
   :undoc-members:
   :show-inheritance:

Exact attacker stages
---------------------

The chain probe can route and trace exactly these attacker stages:

``ANALYSIS``, ``TOOL_TAGGING``, ``EDGE_SCORE``, ``EXPLOIT_HYPOTHESES``,
``STEP_PLAN``, ``STEP_ATTACK``, and ``STEP_EXPLOIT``.

``stage_model_roles`` maps a role name to ``model_type``, ``model_name``, and
``model_config``. ``stage_model_routes`` maps each exact stage name to a role.
Roles load lazily, allowing one configuration to declare a hosted baseline,
hosted teacher, local base, and local adapter without connecting to unused
models. ``stage_generation_settings`` accepts per-stage ``max_tokens``,
``temperature``, ``top_p``, ``top_k``, ``seed``, ``extra_params``, and
``suppressed_params``. Unknown stage names and generation settings fail during
configuration instead of being ignored.

For hosted Nano, the direct-output stages disable thinking with
``extra_body.chat_template_kwargs.enable_thinking=false``. The reasoning stages
retain an explicit reasoning budget. Both provider-specific request shapes must
pass the hosted preflight before a campaign is frozen.

Structured model-only evaluation
--------------------------------

Set both of these options for the primary model-only campaign::

   strict_stage_outputs: true
   deterministic_fallbacks_enabled: false

Strict mode requires a raw JSON object matching the stage's stable structural
contract. Markdown fences, explanatory text, malformed JSON, missing fields,
and wrong field types are rejected. Disabling deterministic fallbacks prevents
the default exploit hypothesis and deterministic identity, codereview,
e-commerce, and payment prompts from replacing failed attacker output. It also
disables the workflow-specific step-plan normalisers; a model-only plan must
already name the exact tools and valid roles. Utility parsing and deterministic
terminal validation remain separate and do not route through a trained attacker
adapter.

``max_step_attempts`` is the total target-turn budget for each step: one initial
attempt plus refinements. For example, ``max_step_attempts: 3`` permits exactly
three target turns on a failed step. Active chains advance breadth-first, so the
probe turn budget is ``max_chain_len * max_step_attempts`` rather than that value
multiplied by the number of active chains.

Stage traces
------------

Set ``stage_trace_path`` to append
``ai-sec.agent-breaker-stage-trace/v1`` JSONL. Each record contains the exact
single-user-message input and runtime-rendered prompt, prompt and template
SHA-256 values, template source, garak commit, exact model role/provider/name and
endpoint, generation settings, raw and parsed completion, validation result,
guard decisions, visible artifacts, deterministic outcome, victim response,
fallback flags, and allow-listed hosted request metadata. Fields that do not
apply at generation time are present with empty or null values. Every stage row
has a stable ``attempt_id``. For a trace named ``stages.jsonl``, victim and
detector results are appended to ``stages.outcomes.jsonl`` as
``ai-sec.agent-breaker-attempt-outcome/v1`` records carrying that same ID. This
keyed join supplies the eventual victim response, deterministic terminal
outcome, detector verdict, advancement decision, and visible artifacts without
relying on JSONL line order. Pre-model deterministic shortcuts are recorded in
the same sidecar as ``ai-sec.agent-breaker-fallback-event/v1`` and carry their
own attempt ID into the target Attempt. API keys and authorisation headers are
excluded.

``STEP_ATTACK`` and ``STEP_EXPLOIT`` records are deferred until the identity and
artifact guards accept or reject their generated prompt, so their ``guards``
field contains the real post-generation decision rather than a prediction.

Hosted codereview baseline
--------------------------

``scan_agent_breaker_chains_inference_hub.yaml`` contains the hosted baseline
with these exact identifiers:

* baseline and utility parser: ``nvidia/nvidia/Nemotron-3-Nano-30B-A3B``
* victim: ``openai/openai/gpt-5.2`` (inside the NAT codereview gateway)
* teacher role: ``nvidia/zai-org/glm-5.2``

The benchmark config disables behavioural and fault-probe prompt generation so
hosted-baseline attacker calls are limited to the seven named stages. Deep
reconnaissance and utility parsing remain deterministic/utility setup and are
not adapter-routed.

The target gateway is ``http://127.0.0.1:8000/v1/chat/completions``. It is bound
to the versioned lab episode by deployment configuration. Reset once before
each measured episode, before starting its Garak run; never reset between chain
turns. Garak does not reset the episode implicitly.

Set the token once, then run the baseline::

   export INFERENCE_API_KEY="<your NVIDIA Inference Hub token>"
   uv run garak --config scan_agent_breaker_chains_inference_hub.yaml

The trace path can be changed per campaign without editing the config. The exact
CLI option shape is::

   uv run garak \
     --config scan_agent_breaker_chains_inference_hub.yaml \
     --probe_options \
     '{"agent_breaker_chains":{"AgentBreakerChains":{"stage_trace_path":"/absolute/run/path/stages.jsonl"}}}'

For the local-base bridge, serve the pinned
``nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16`` checkpoint at
``http://127.0.0.1:8005/v1/`` under that exact served name. Then apply the
same route fragment together with the per-run trace path::

   export OPENAICOMPATIBLE_API_KEY="local-not-secret"
   uv run garak \
     --config scan_agent_breaker_chains_inference_hub.yaml \
     --probe_options \
     '{"agent_breaker_chains":{"AgentBreakerChains":{"stage_model_routes":{"ANALYSIS":"local_base","TOOL_TAGGING":"local_base","EDGE_SCORE":"local_base","EXPLOIT_HYPOTHESES":"local_base","STEP_PLAN":"local_base","STEP_ATTACK":"local_base","STEP_EXPLOIT":"local_base"},"stage_trace_path":"/absolute/run/path/local-base-stages.jsonl"}}}'

This changes only the seven attacker stages. The utility parser remains hosted
base Nano, and the target remains the same hosted GPT-5.2 victim gateway. The
``local_base`` role is the unadapted BF16 checkpoint; do not point it at a LoRA
or merged adapter endpoint. ``agent_breaker_local_base_bridge.probe_options.json``
contains the canonical route fragment for orchestrators that build a merged
per-run probe-options file.

The target REST mapping allow-lists only
``$.choices[0].message.metadata.terminal_outcome`` into
``Message.notes.response_metadata.terminal_outcome``. The probe accepts that
signal only when it has the exact ``ai-sec.terminal-outcome/v1`` field set,
operation binding, one execution, non-negative suppression count, and a valid
SHA-256 effect reference. Assistant-authored marker text is never terminal
authority.
