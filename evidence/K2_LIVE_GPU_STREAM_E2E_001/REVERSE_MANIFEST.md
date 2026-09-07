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

## Closed
| Gate | Status | Authority class |
|------|--------|-----------------|
| `K2_SHARD_ATTN_RESIDENCY_001` | PASS | SHARD_IO=0 |
| `K2_LOGITS_Q6K_RESIDENT_001` | PASS | packed Q6_K |
| `K2_SEMANTIC_SEAL_001` | PASS | q_b=12288, vocab, deepseek chat |
| `K2_SERVERLESS_STREAM_LATENCY_001` | PASS | sticky TTFT/DECODE |
| `K2_WALL_ATTRIBUTION_002` | PASS OWNER=MLA | stage OWNER=KV_EXPAND |

## Semantic note
Tensor `attn_q_b` is **[1536,12288]**. Engine scratch still logs `q_b=8192`
(=64×128). Correctness authority is the tensor (12288=64×(128+64)).

## Do not
- Predetermine `MLA_FUSED_Q4KT` when stage owner is KV_EXPAND
- Conflate semantic q_b seal with wall ownership
