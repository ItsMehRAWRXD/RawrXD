# K2_WALL_ATTRIBUTION_001 — REVERSE MANIFEST

## Seal
`K2_WALL_ATTRIBUTION_001=PASS` (2026-09-07)
Evidence: `RUN_LOG.txt`, `GATE_STATUS.txt`

## Freeze (sustained winner — held)
```text
D=61 CACHE_N=366 PIN≈3673 MiB FULL_DEPTH_PROMO
TRY=0 UP/tok=0 HIT/tok=366 pinRej=upFail=fb=pta=0
OPS=6×D×T exact
```

## Attribution (timed windows, ms/token)
| Window | MLA | LOGITS | SHARD_IO | OTHER | MAX |
|--------|-----|--------|----------|-------|-----|
| W32 | 222.9 | **442.8** | 0 | 35.3 | LOGITS |
| W64 | 205.9 | **412.6** | 0 | 23.2 | LOGITS |
| W128 | 220.3 | **455.4** | 0 | 21.2 | LOGITS |

OWNER total ms across W32+W64+W128: **LOGITS ≈ 98867 ms** (MLA ≈ 48512).

SHARD_IO after warm: calls=0 bytes=0 (host MLA pin + trampoline output.weight).
SAMPLE/DETOK/STREAM: negligible.

## NEXT_BEST_MOVE
```text
NEXT_CLIMB=K2_LOGITS_CLIMB
```
Attack **only LOGITS** (Q6_K packed vocab argmax / ProjectLogitsArgmax).
Do **not** retune MLA. Do **not** open SHARD_IO climb (0 ms).
If a future climb leaves OTHER dominant, split OTHER — do not optimize known lanes.

## Harness
`DEEP2_CERT_STEP_LOG=1` → `[CERT_STEP]` + fflush (diagnostic only).
