# B03 MiniMax — quality gate (OPEN)

`PROMOTE=0` · `CERTIFIED=0` · `REFERENCE_PARITY=NOT_ESTABLISHED` · `CROSS_SHA_CREDIT=0`

Controlling smoke: `minimax_b03v.*` · EXE `EXE_SHA256.txt` =
`31A95B019CADEB2CC492DDB99B3690575EC4E09DFC92052953F689910E71B586`

## Measured this batch

| Gate | Result |
|------|--------|
| B03_QKV_MAXABS L0 post QK-norm | **q≈1.1e1 k≈6.3e0 v≈2.8e1** (finite; not 1e24) |
| ropeDim / headDim | **64 / 128** (partial RoPE freq base = ropeDim) |
| ChatTemplate | Forced **minimax** (`]~b]user` / `]~b]ai`) |
| PROMPT_TOKENS | 50 |
| GENERATED_TOKENS | 4 |
| ACQUIRE_OK | 26288 · ACQUIRE_DENIED=0 |
| Decoded output | `\n\nDiset在现场` — **QUALITY OPEN** |
| B03_HIDDEN_SANITIZE | **removed** (no mask/rescale) |
| PHYSICAL REAP export | NOT_CLAIMED (`writer_invoked=false`) |

## Source defects corrected

1. **QK-Norm per-head weight offset** — `attn_q_norm`/`attn_k_norm` are
   `[n_head*headDim]`; prior path reused head-0 weights for every head.
2. **Partial RoPE frequency** — `initRoPETables` now uses
   `rope.dimension_count` (64) as the freq denominator, not `headDim` (128).
3. **Hidden sanitize mask removed** — explosions report `B03_HIDDEN_EXPLODED`
   without unit-RMS rescale.
4. **MiniMax chat template** — stop forcing DeepSeek ChatML; emit native
   `]~!b[]~b]system` / `]~b]user` / `]~b]ai` / `<think>` markers.

## Issue #83 source integrity

Branch `evidence/reap-multi-model-20261113` GitHub blob for
`src/deep2/MoERouter.cpp` is **UTF-16LE** (size 26086, head `2F-00-2F-00…`).
Local feature / this worktree copy is **UTF-8** (13198 bytes, no NULs).
`MultiShardWeightBind.hpp` is present on the feature product path; **404** on
the evidence tip until landed.

## Disposition

```
B03_E=PASS_REPORTED
MINIMAX_QUALITY=OPEN
REFERENCE_PARITY=NOT_ESTABLISHED
MOEROUTER_UTF16_ON_EVIDENCE_BRANCH=CONFIRMED
MOEROUTER_UTF8_LOCAL=1
PROMOTE=0
CERTIFIED=0
```
