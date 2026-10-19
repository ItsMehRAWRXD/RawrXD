RAWRXD DEEP2 PORTABLE NO-STREAM SOURCE DROP
========================================
This drop converts the residency contract from background/predictive streaming to
foreground demand loading. It does NOT claim that a 376.65 GiB model can be fully
resident in RAM/VRAM. Exact file reads still occur during inference, but only when
the current graph operation or real MoE Top-K requires them.

Core:
  deep2_nostream.[ch] - allocation-free, thread-free route residency authority.
  deepseek2_671b_profile.h - values decoded from the supplied real GGUF header.
  deep2_hotpatch_contract.h - compile-time policy contract.
  gguf_v3_numeric_probe.c - proper GGUF KV walker for numeric/string deepseek2 keys.
  audit_deep2_nostream.ps1 - residual source scanner.
  INTEGRATION_MAP.txt - exact active paths to neutralize and replacement semantics.

Important:
  The model is 11 shards. A shard-aware GGUF tensor index must map each requested
  object/expert pack to its exact shard/offset/range. The callback supplied to
  d2ns_init owns that mapping and the actual synchronous read/load operation.

For packed DeepSeek expert tensors, load callback(object_id) must materialize the
selected expert's gate/up/down slices (or an equivalent kernel-ready pack), not the
entire 256-expert tensor unless intentionally budgeted.

Raw prompt text cannot know every future expert. Each router operates on a hidden
state created by earlier layers. Therefore the only correctness-preserving no-
background rule is: route first, synchronously require exact Top-K, execute, continue.

No authority is minted here:
  DECODE_AUTHORITY=UNCHANGED
  SCHEDULER_AUTHORITY=UNCHANGED
  AUTHORIZED_PASS=0
  PROMOTE=0
