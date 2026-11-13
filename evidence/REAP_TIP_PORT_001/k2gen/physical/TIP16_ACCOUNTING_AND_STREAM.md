# Tip16 — Complete expert-byte accounting + stream correctness

## Gate1 — accounting reconciliation

Independent offset inventory (`inv_offsets.py` / `GATE1_FULL_INVENTORY.json`):

| Quantity | Bytes |
| -------- | ----- |
| Disk (13 shards) | 621 245 224 864 |
| Routed expert tensors (`*_exps`) | 612 907 352 064 |
| Shared keep (attn/embed/dense/router/shexp/other) | 8 330 889 216 |
| Bytes / expert (all 60 MoE layers) | 1 596 112 896 |

With `--reap 30GB/8` → `target_working_set_bytes ≈ 19.5e9`:

\[
R = \max\!\left(8,\ \left\lfloor\frac{\mathrm{budget}-\mathrm{keep}}{\mathrm{bytes\_per\_expert}}\right\rfloor\right) = 8
\]

\[
\mathrm{REPACKED} = \mathrm{keep} + 8\cdot\mathrm{bytes\_per\_expert} \approx 21.1\,\mathrm{GB}
\]

**Tip15 error:** shard-0-only inventory undercounted routed expert bytes → inflated `RETAINED_EXPERT_COUNT=149`.  
**Tip16 fix:** all-shard `GGUFLoader::Load` tensor-size sum; `ACCOUNTING_COMPLETE=1`.

The ~3.4% of disk figure is **consistent**: routed experts are ~98.7% of the GGUF. It is **not** a certified standalone executable GGUF — receipt notes `REPACKED_SCOPE=SHARED_KEEP_PLUS_RETAINED_ROUTED_EXPERTS` and `NOTE=…NOT_A_CERTIFIED_STANDALONE_GGUF`.

`PRUNED_ROUTED_EXPERT_BYTES` replaces the misleading Tip15 `PRUNED_PARAMETER_COUNT` label (those were bytes, not params).

## Gate3 — stream correctness

Counters on physical bank:

- `ROUTE_OK` / `ROUTE_DENIED` (fail-closed if denied)
- `ACQUIRE_OK` / `ACQUIRE_DENIED`
- `TOPK_MISMATCH`
- `stream_correctness.PASS` iff no route denial and no top-k mismatch

## Still OPEN

- Calibration-ranked selection
- `transformMoEGGUF` sidecar export
- Quality / reference validation
- `PROMOTE=0`
