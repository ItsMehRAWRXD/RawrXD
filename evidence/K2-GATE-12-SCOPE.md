# K2 Gate 12 — Scope (NOT PROVEN)

**Status:** NOT PROVEN / OPEN  
**Prerequisite:** G10 and G11 remain PASS / frozen — G12 is additive only.

## Goal

Complete MLA attention math inside `MLAForward::Execute` without reopening the 4-layer bounded stream gates:

```text
RoPE on k_pe / q positions
→ attention scores (Q·K)
→ softmax over KV length
→ weighted V aggregation
→ output projection (attnO)
→ KV cache read/write via K2KVCache
```

## Current gap (src/deep2/K2MLAWeights.cpp)

`MLAForward::Execute` performs Q/K/V GEMVs but explicitly notes:

> A full implementation would do RoPE, score computation, and softmax.

The stream path uses this simplified forward for 4 layers — sufficient for execution witness, insufficient for coherence.

## Proposed Gate 12 contract (draft)

```text
GATE_12_MLA_ATTENTION_COMPLETE     PASS
ROPE_APPLIED                       PASS
SOFTMAX_FINITE                     PASS
KV_CACHE_WRITE                     PASS
KV_CACHE_READ                      PASS
LAYER_DEPTH                        = 4  (unchanged from G10/G11)
PEAK_RESIDENCY_MIB                <= 256
FINAL_RESIDENCY_MIB               = 0
G10_G11_UNCHANGED                  PASS (regression)
FALLBACK                           = NONE
```

## Out of scope for G12

- MoE routing (G13)
- 61-layer forward (G14)
- Semantic coherence / deterministic generation (G15)

## Harness direction

New additive target or gate flag (e.g. `--run-generation-mla-g12`) that exercises `MLAForward` with KV cache on a single-token step — not replacing G10/G11 validators.
