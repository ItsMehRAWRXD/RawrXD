# Q6K_VULKAN_SPV_REPAIR_001 — Disposition

```text
PACK=Q6K_VULKAN_SPV_REPAIR_001
ASOF_LOCAL=2026-11-14T11:13:37-05:00
Q6K_VULKAN_SPV_REPAIR=PASS
PROMOTE=0 CERTIFIED=0 GATE_STOP=1 TIP_CLIMB=HOLD
INVENT_PASS=0 CROSS_SHA_CREDIT=0 NOT_RUN!=PASS
```

## Verdict

`DEEP2_Q6K_FORCE_VULKAN_SPV=1` on measured EXE `7C9680CB…` (Method C tip) produces finite L0 `v_proj` via `gemv_q6k.spv`, zero `FIRST_NONFINITE`, zero `Q6K_HOST_GEMV` lines, `GENERATED_TOKENS=8`, coherent stdout `Yes, 2 + 2 =`, `CLEAN_EXIT=1`. Independent remasure on later tip `CEBA0DE4…` (product-default SPV sister) also FORCE_SPV finite+coherent (`CROSS_SHA=0`).

This closes the Moves-Complete **Q6K_VULKAN_SPV_REPAIR** owner for the FORCE_SPV product path. It does **not** lift `PROMOTE`, enterprise CERT, or multi-family gates.

## Root cause

| Item | Value |
|------|-------|
| Class | `PREFETCH_ACT_ABI_MISMATCH` |
| Site | `SubmitGemvPrefetch` bound `block_q8_K[]` into `gemv_q6k.comp` `In float x[]` |
| Fix | Float activation bind; on-shader Q8_K (R103 / `f9438103b4`) |
| Shader arith | Not the NaN root |

## Separations (must hold)

| Claim | Status |
|-------|--------|
| Hybrid host on `9797521C` | Workaround seal; ≠ this PASS |
| R103 EXE `E7797EE8` | RELATED prior; CROSS_SHA=0 vs tip |
| Product default HOST | Retained on measured tip (`forceQ6kSpv` opt-in) |
| Dirty worktree SPV-default flip | Not measured; not sealed |
| `PROMOTE` / CERT / 8 TPS climb | Forbidden / held |

## Next

`NEXT_OWNER=REAP_LAGUNA|Move51+`
