# K2_LIVE_DECODE_SUSTAINED_001 — REVERSE MANIFEST

## Seal
`K2_LIVE_DECODE_SUSTAINED_001=PASS` (2026-09-07)
Evidence: `RUN_LOG_ELIM2.txt`, `GATE_STATUS.txt`
Serverless spine: `evidence/K2_LIVE_GPU_STREAM_E2E_001/REVERSE_MANIFEST.md`

## Path (real)
```text
CommandLine → sustained_cert
  → generateStream → runK2NativeStreamPartial
  → MLA_Gemv (Q4+Q8) | GetGEMV
  → ProjectLogitsArgmax → ghostTok → DecodeToken
```

## Process of elimination (MoE blanks)
| Set | Action |
|-----|--------|
| **USED** | MLA dense pins (`layer<<8\|tag`) — 366 keys, ~3.6 GiB resident |
| **BLANK** | Never-acquired MoE experts → `moeHotExpertCount=0` |

`MOE_USED=0`: experts never hit `MoEWeightProxy::Acquire`. Old ~0.33 U/OPS was
**Q+O pin thrash**, not MoE.

## What fixed U→0
1. Pin key `thread_local` → `atomic` (TLS drift → `pinKey=0` → fingerprint thrash)
2. Sticky pin budget floor (8784 MiB)
3. Don’t `Fused_Reset` between `generateStream` windows

## Sealed rates (after warm pins)
```text
U32=U64=U128=0.000   COLLAPSE=1
H/tok=366 flat       (= 6×61 unique GEMVs/token)
U128/OPS=0           STRONG=1
EVICT=0  CACHE_N=366  GROWTH0=1
OPS = 6×D×T exact; TRYGPU_ENTRY=0; pinRej=upFail=fb=pta=0
RES flat ~3673 MiB
```

## Fiction → reality
| Fiction | Reality |
|---------|---------|
| W128 crashes after LIVE_SETUP | W128 runs ~61s; stdout buffered under redirect |
| Competing build-fd vs ninja | Same gate; exclusive GPU required |
| Q4_ONLY default | Q8 ON unless DEEP2_MLA_GPU_Q4_ONLY=1 |
| Need MoE→VRAM to sustain | MoE is BLANK on this path |

## NEXT_BEST_MOVE
(Continues on serverless byteless spine — elimination of wall owners only.)
1. `K2_LOGITS_Q6K_RESIDENT_001` (SHARD_ATTN already PASS)
2. Semantic seals (tiktoken / `q_b=12288` / chat template) — independent
3. `MLA_FUSED_Q4KT` retune only if GEMV dominates post-semantic
