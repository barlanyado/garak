garak.generators.nvidia_inference
=================================

.. automodule:: garak.generators.nvidia_inference
   :members:
   :undoc-members:
   :show-inheritance:

``NVIDIAInferenceHub`` uses the OpenAI-compatible NVIDIA Inference Hub endpoint
and reads authentication only from ``INFERENCE_API_KEY``. Model identifiers are
passed to the API exactly as configured; case and repeated organisation segments
are not normalised.

The default endpoint is ``https://inference-api.nvidia.com/v1/``. A different
endpoint can be supplied through the generator's ``uri`` setting, but it must be
credential-free HTTPS with no query string or fragment. Inline credentials are
rejected throughout the configuration, including nested headers and query
parameters. ``extra_params`` cannot replace ``model``, ``messages``, ``n``, or
``stream``. Returned messages contain only allow-listed request metadata:
request and response IDs, latency, token usage, status, and rate-limit values.
Credentials and arbitrary HTTP headers are never placed in message notes.

``LocalOpenAICompatible`` applies the same response-provenance checks to a local
OpenAI-compatible server. Its URI must use credential-free loopback HTTP. The
client uses an internal non-secret placeholder, does not read the hosted token,
and rejects a returned model identifier that differs from the requested model.

Example::

   export INFERENCE_API_KEY="<your NVIDIA Inference Hub token>"
   uv run garak \
     --target_type nvidia_inference.NVIDIAInferenceHub \
     --target_name nvidia/nvidia/Nemotron-3-Nano-30B-A3B \
     --probes test.Blank

Use ``extra_params.extra_body`` for endpoint-specific reasoning controls. Check
support with a minimal request before a campaign; requested model identifiers
must not be silently substituted after a 4xx response.
