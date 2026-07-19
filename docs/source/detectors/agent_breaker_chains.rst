garak.detectors.agent_breaker_chains
====================================

.. automodule:: garak.detectors.agent_breaker_chains
   :members:
   :undoc-members:
   :show-inheritance:

``AgentBreakerChainResult`` scores the terminal exploit step of a multi-tool
chain. Reconnaissance, pivot, and plant steps are normally scored as non-hits;
an intermediate attempt explicitly marked as an incidental finding is still
passed to the underlying security verifier.

Terminal outcomes with suppressed duplicate sink calls are rejected as clean
chain evidence. This preserves the distinction between a single accepted
terminal action and an at-most-once guard blocking repeated execution.
