# REVERSE MANIFEST — K2_LOGITS_Q6K_RESIDENT_001

## Seal
`K2_LOGITS_Q6K_RESIDENT_001=PASS` (2026-09-07)
Evidence: `RUN_LOG_FUSED.txt`, `GATE_STATUS.txt`

## Hard invariants (sealed timed arm)
```text
Q6 packed resident     outWBytes=963379200 (~918 MiB)
hot uploads = 0
full vocab dequant = 0
full logits materialization = 0
argmax parity FAIL = 0
SHARD_ATTN_US = 0  HOST_CACHE_COPY_US = 0  OUT_W_US = 0
LOGITS_SHARD_ROW_READS = 0
```

## Not an F32 warehouse
```text
packed ≈ 0.9 GiB
F32 vocab warehouse would be ≈ 4.4 GiB (163840×7168×4)
gate rejects outWBytes ≥ warehouse/2
```

## Spine position
```text
SUSTAINED → WALL_ATTRIBUTION_001 (OWNER=LOGITS)
  → K2_LOGITS_Q6K_RESIDENT_001  ← HERE (PASS)
  → semantic seals (independent)
  → latency buckets
  → WALL_ATTRIBUTION_002
  → if OWNER=MLA then MLA_FUSED_Q4KT else attack measured owner
```

## Note
LOGITS_US still ~1.2e6 on T=8 — residency sealed; wall climb of the
packed argmax itself is a later OWNER re-measure, not an F32 rewrite.
