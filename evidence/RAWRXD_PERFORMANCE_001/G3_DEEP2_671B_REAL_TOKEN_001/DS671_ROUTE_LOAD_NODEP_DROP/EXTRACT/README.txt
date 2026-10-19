RAWRXD DS671 ROUTE-TRIGGERED EXPERT LOAD HOTPATCH
================================================

Purpose
-------
Replace sequential whole-model expert streaming with route-triggered exact
expert loading. The user input produces hidden activations; the real DeepSeek
router selects Top-K experts; only those selected routed experts are requested
from the caller's existing GGUF/tensor loader.

This is NOT predictive magic:
- The router decision for a later layer depends on earlier layer results.
- Therefore every future expert choice cannot be known from raw text alone.
- The patch hooks AFTER each real router result.
- Unexpected decode experts either load synchronously (GROW_NO_EVICT) or fail
  closed (STRICT_PROMPT_ONLY).

No background streaming
-----------------------
NO_BACKGROUND_THREAD=1
NO_SEQUENTIAL_EXPERT_SCAN=1
NO_PREFETCH_QUEUE=1
NO_EVICTION=1
ROUTER_SELECTED_LOAD_ONLY=1
CALLER_OWNS_FILE_IO=1

The module has no allocator, no filesystem dependency, no STL, and no model
format dependency. Caller supplies an arena and three callbacks:
measure_expert, load_expert, release_expert.

Why this targets DeepSeek 671B
------------------------------
The official DeepSeek-V3 671B config has 61 transformer layers, 3 dense layers,
256 routed experts in each MoE layer, and 8 activated routed experts. This
gives 58 MoE layers. The module indexes those 58 x 256 routed-expert slots
without allocating internally.

Correct integration order
-------------------------
hidden
  -> router scores
  -> exact Top-8 IDs
  -> ds671_require_route()
  -> returned expert handles
  -> expert forward
  -> weighted combine

Do NOT call this before the router. Raw prompt token IDs are insufficient to
know every layer's expert selection.

Modes
-----
DS671_MODE_STRICT_PROMPT_ONLY:
  Prompt may load experts. After ds671_seal_prompt(), a never-seen expert
  causes DS671_E_DECODE_MISS. Best for proving prompt-footprint stability.

DS671_MODE_GROW_NO_EVICT:
  Decode may synchronously add a newly selected expert if budget remains.
  Nothing is evicted and there is no background streaming.

Fail-closed
-----------
Any bad expert id, duplicate Top-K id, missing callback, zero measured size,
size mismatch, budget overflow, failed load, or strict-mode decode miss returns
an error. ds671_require_route() moves the context to FAILED on route failure.

Scope
-----
This patch solves only routed-expert residency dispatch. It does not implement:
MLA, router math, shared experts, dense FFNs, GGUF parsing, quant kernels,
scheduler authority, decode authority, or promotion authority.
