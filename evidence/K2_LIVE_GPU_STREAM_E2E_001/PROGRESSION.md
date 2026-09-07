# K2 GPU stream progression

```text
PARITY / Vulkan MLA / pin-reuse / REBENCH
    → PROMOTE_GPU_MLA                    SEALED
K2_MLA_FULL_DEPTH_SOAK_001               PASS (D=61 durability)
──────────────────── plumbing boundary ────────────────────
K2_LIVE_DECODE_MLA_001                   PASS (real generate @D=61)
K2_LIVE_DECODE_SUSTAINED_001             PASS (warm2×8 → 32/64/128)
K2_WALL_ATTRIBUTION_001                  PASS → OWNER=LOGITS
K2_GPU_MLA_LIVE_001                      SUPERSEDED
```

## Authority (frozen)
```text
Live callers → MLA_Gemv ONLY
MLA_Gemv → Q4 GPU | Q8 GPU | GetGEMV
MLA_TryGpuGemv → GPU attempt primitive (TRYGPU_ENTRY must stay 0)
```

## Sustained D=61 (measured — RUN_LOG_ELIM2.txt)
| Window | OPS | UP | HIT/tok | tps (wall) | pinRej |
|--------|-----|----|---------|------------|--------|
| WARM0/1 | 2928/2928 | fill | — | ~1.4 | 0 |
| W32 | 11712/11712 | **0** | 366 | 1.798 | 0 |
| W64 | 23424/23424 | **0** | 366 | 1.652 | 0 |
| W128 | 46848/46848 | **0** | 366 | 2.098 | 0 |

Pins: CACHE_N=366 RES≈3673 MiB flat. U/tok collapse=1 H/tok flat=1 STRONG=1.

**Fiction corrected:** W128 “crash” was ~61s decode + redirected stdout with no mid-window flush.
Do not kill the process while log is silent after `LIVE_SETUP ok`.

## Wall attribution (K2_WALL_ATTRIBUTION_001)
OWNER=**LOGITS** (~413–455 ms/tok). MLA second (~206–223). SHARD_IO=0 after warm.
Freeze held: UP=0 HIT/tok=366 CACHE_N=366 TRY=0.

## Next
`K2_LOGITS_CLIMB` — attack ProjectLogitsArgmax / Q6_K vocab only.
No MLA retune. No SHARD_IO climb.
