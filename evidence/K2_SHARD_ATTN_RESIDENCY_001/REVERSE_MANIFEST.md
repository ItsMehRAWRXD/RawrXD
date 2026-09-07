# REVERSE MANIFEST — K2_SHARD_ATTN_RESIDENCY_001

## Seal
`K2_SHARD_ATTN_RESIDENCY_001=PASS` (2026-09-07)
Evidence: `RUN_LOG_FUSED.txt`, `GATE_STATUS.txt`

## Wall owner (prior attribution → this gate)
```text
SHARD_ATTN  ~44%  ← ELIMINATED (timed arm)
LOGITS_Q6K  ~32%  ← NEXT: K2_LOGITS_Q6K_RESIDENT_001
MLA         ~17%
OUT_W       ~7%
```

## Law
```text
ResolveWeight(tensor)
  retained cache valid → BorrowSpan (≠ memcpy ≠ upload ≠ remap)
  absent → shard read → Put → BorrowSpan

One resolver / one ownership. Pin+cache lifetime outside generateStream teardown.
```

## Bypass killed
```text
551-entry cache existed ≠ timed consumers borrowed it

1. ResolveWeight TryGet first (sticky MLA; no MayCache gate)
2. K2LiveCache_Clear retains sticky MLA + output.weight + output_norm.weight
3. LoadTensorPayload: sticky names never HOST_CACHE_COPY (borrow≠memcpy)
4. output_norm → ResolveWeight borrow (not LoadTensorPayload copy)
5. DEEP2_K2_GPU_MLA=1 keeps shard IO handles across warm→timed
```

## Timed invariants (sealed)
```text
SHARD_ATTN_BYTES/token = 0
SHARD_ATTN_READ_CALLS/token = 0
SHARD_ATTN_REOPEN = 0
SHARD_ATTN_MAPFAULT_CRITICAL = 0
ATTN_RESOLVE_TOTAL = ATTN_RESOLVE_CACHE = 4392
ATTN_CACHE_KEY_MISS = 0 (all miss reasons 0)
ATTN_SHARD_BYTES = 0
MLA uploads/token = 0  HIT=2928
HOST_CACHE_COPY_US = 0
TRY_EXT = 0  FB = 0
cacheN = 551
```

## Warm vs timed (authority proof)
| Arm | SHARD | CACHE | KEY_MISS | HOST_COPY | MLA_UP |
|-----|-------|-------|----------|-----------|--------|
| WARM | 549 | 3843 | 549 | 0 | 366 |
| TIMED | 0 | 4392 | 0 | 0 | 0 |

## Expected wall delta (from prior D=61/T=8 attribution)
```text
11.0 s → ~6.2 s  (~1.77×) once SHARD_ATTN stays flat at 0
```

## NEXT_BEST_MOVE
`K2_LOGITS_Q6K_RESIDENT_001` — reverse Q6_K output projection:
dequant vs shard traffic vs host materialize vs launch/dispatch per token.

Do **not** retune fused MLA / `MLA_FUSED_Q4KT` until logits wall is attributed.
