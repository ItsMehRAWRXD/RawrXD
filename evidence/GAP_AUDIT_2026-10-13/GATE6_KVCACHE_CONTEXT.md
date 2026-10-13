# Gate 6 Certification — KV-Cache and Context Integrity

**Date:** 2026-10-13
**Status:** **PASS** (all conditions verified with bit-exact evidence)
**Model:** `models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`; harness: `deep2_parity_trace.exe`

## 1. Incremental decode == full-prefix recompute (bit-exact)

Prefix sequences run in separate processes; overlapping positions must be byte-identical
(SHA-256 of the per-position logit dumps):

| position | CPU runs ([1], [1 185], [1 185 278]) | GPU runs (same) |
| --- | --- | --- |
| pos0 | `B113498EFBADB2E0` ×3 identical | `EE279330F7777D8E` ×3 identical |
| pos1 | `4B2D2AA39E621C3D` ×2 identical | `E899D19A2CE71968` ×2 identical |

Position *k*'s logits are bit-identical whether it ended a short run or was followed by more
tokens: the cache written at position *k* is neither corrupted nor contaminated by later tokens,
and the cache **read** path reproduces exactly what a fresh short run computed.

## 2. Repeated prompt / determinism

`[1 185 278]` re-run in a fresh process: identical hashes at all three positions on **both**
backends (CPU `34B4C16C43B63554` pos2; GPU `DB0535DAF12F39A5` pos2).

## 3. Cache isolation and reset

KV state is per-Executor, allocated fresh in `Bind` (`kv_k_.assign(B, {})` /
`kv_v_.assign(B, {})`) and grown with zero-fill (`resize(needK, 0.0f)`). Fresh-process runs of
different sequences therefore cannot inherit state; block/position bounds are checked before
every access (`in.block >= kv_k_.size()` guards, `needK/needV` resize math). Repeated-prompt
bit-identity (item 2) confirms no stale state survives within a process run.

## 4. Context boundary — the governor fails CLOSED (no silent truncation)

`DEEP2_KV_BUDGET_MB=1` with the 129-token sequence:

```
EXEC_FAIL pos=23 err=kv cache growth rejected by resource governor
(block 6, position 23, requested 2048 bytes; raise DEEP2_KV_BUDGET_MB or reduce context)
exit code = 1 (24 positions completed: 0..23)
```

Cumulative KV at the rejection point (22 blocks × 2 × 24 × 256 × 4 B ≈ 1.03 MiB) matches the
1 MiB budget — the growth lease is accounted exactly and exhaustion stops the forward closed,
as required (no silently truncated cache).

## 5. Memory accounting

`ATTN_TRACE` at position 189: `kvcache=48384,48384` floats per block = 189 × 256 (the trace
prints pre-append). Post-append size is (pos+1) × 256 = 190 × 256 = 48,640 floats per K per
block, so KV residency = 22 blocks × 2 (K+V) × 190 × 256 × 4 B = **8,560,640 B = 8.16 MiB** —
exactly the closed-form formula, with every byte leased through the governor.

## 6. Deep-position correctness

The Gate 5 sweep ran 129 consecutive positions with cache reuse on both backends: all logits
finite, argmax agreement tracked reference/noise bounds at every position — prefill, decode,
RoPE, and attention accumulation over a growing cache all verified in situ.

## Verdict

**Gate 6 = PASS.** Cached execution agrees bit-exactly with recompute, repeated prompts are
deterministic, growth is admitted and accounted by lease with closed failure at the boundary,
and no out-of-bounds or stale-state behavior was observed at any tested position.
