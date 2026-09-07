# REVERSE MANIFEST — K2 GPU MLA / Live stream (serverless byteless)

Spine separates **elimination evidence**, **semantic correctness**, and
**performance ownership**. One never implies the others.

## Continuation chain
```text
K2_LIVE_DECODE_SUSTAINED_001          ← elimination (USED pins / MoE BLANK)
        ↓
K2_WALL_ATTRIBUTION_001               ← OWNER measurement only
        ↓ OWNER=LOGITS
K2_LOGITS_Q6K_RESIDENT_001            ← packed Q6_K reuse (not F32 warehouse)
        ↓
semantic seals ───────── independent correctness authority
        ↓                  (tiktoken / q_b=12288 / chat template)
latency buckets
        ↓
K2_WALL_ATTRIBUTION_002
        ↓
if OWNER=GEMV/MLA → MLA_FUSED_Q4KT
else              → attack measured owner
```

## Closed
| Gate | Status | Authority class |
|------|--------|-----------------|
| `K2_MLA_REUSE_PROMOTE_001` | PASS | elimination / MLA reuse |
| `K2_LIVE_DECODE_MLA_001` | PASS | authority MLA_Gemv |
| `K2_MLA_FUSED_Q4KT_001` | PASS | fused vs compat (frozen until OWNER=MLA) |
| `K2_LIVE_DECODE_SUSTAINED_001` | PASS | elimination residency |
| `K2_TPS_RAINBOW_001` | PASS | stream-norm (not wall) |
| `K2_SHARD_ATTN_RESIDENCY_001` | PASS | SHARD_IO=0 borrow |
| `K2_WALL_ATTRIBUTION_001` | run → OWNER | performance ownership |
| `K2_LOGITS_Q6K_RESIDENT_001` | NEXT | packed Q6_K resident |

## Law
```text
REQUESTLESS ≠ STATELESS MODEL
live MLA → MLA_Gemv only (TRYGPU_ENTRY=0)
ResolveWeight → BorrowSpan (≠ memcpy ≠ upload ≠ remap)
USED pins stay; BLANK tensors never acquired
MLA frozen unless post-logits attribution makes GEMV the owner again
```

## Sustained elimination (sealed)
| Set | Action |
|-----|--------|
| **USED** | MLA dense pins — 366 keys, ~3.6 GiB |
| **BLANK** | MoE experts (`MOE_USED=0`) |

U→0 fixes: pin key TLS→atomic; sticky budget floor; no `Fused_Reset` between windows.
```text
U32=U64=U128=0  H/tok=366  EVICT=0  CACHE_N=366
```

## LOGITS hard invariants (`K2_LOGITS_Q6K_RESIDENT_001`)
```text
Q6 packed resident          (output.weight bytes ≈ packed, ≪ F32 warehouse)
hot uploads = 0
full vocab dequant = 0
full logits materialization = 0   (greedy argmax)
argmax parity                 (best beats probe set)
SHARD_ATTN / HOST_CACHE_COPY = 0 on timed arm
```
`resident` must **not** silently become an F32 vocab warehouse.

## Do not
- Predetermine `MLA_FUSED_Q4KT` as destination before OWNER re-measure
- Pin MoE “just in case”
- Replace MLA_Gemv with MLA_TryGpuGemv
- Conflate semantic seals with wall ownership
