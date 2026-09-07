# REVERSE MANIFEST — K2 GPU MLA / Live stream (serverless byteless)

Spine separates **elimination evidence**, **semantic correctness**, and
**performance ownership**. One never implies the others.

## Continuation chain
```text
K2_LIVE_DECODE_SUSTAINED_001
        ↓
K2_WALL_ATTRIBUTION_001               OWNER=MLA (pre-semantic)
        ↓
K2_LOGITS_Q6K_RESIDENT_001            packed Q6_K (not F32 warehouse)
        ↓
K2_SEMANTIC_SEAL_001                  q_b=12288 / vocab / chat  ← PASS
        ↓
K2_SERVERLESS_STREAM_LATENCY_001      TTFT/DECODE buckets     ← PASS
        ↓
K2_WALL_ATTRIBUTION_002               OWNER=MLA; stage=KV_EXPAND ← PASS
        ↓
attack measured owner (KV_EXPAND) — MLA_FUSED_Q4KT only if GEMV owns stage
```

## Closed (latest)
| Gate | Status |
|------|--------|
| `K2_SEMANTIC_SEAL_001` | PASS q_b tensor=12288 |
| `K2_SERVERLESS_STREAM_LATENCY_001` | PASS |
| `K2_WALL_ATTRIBUTION_002` | PASS was OWNER=MLA/KV_EXPAND |
| fused `MLA_KvExpand` live | OWNER stage flipped → **QKV_PROJ** |

## NOW
Attack **QKV_PROJ** (GEMV / fused Q4KT path) — KV expand is no longer the stage max.
Engine buffer `q_b=12288` sealed at alloc (was 8192).
