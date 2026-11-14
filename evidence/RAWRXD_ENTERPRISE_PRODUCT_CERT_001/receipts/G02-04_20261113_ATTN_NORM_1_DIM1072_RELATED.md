# G02-04 RELATED — ATTN_NORM_1@dim1072 bitexact attempt (OPEN)

GATE_ID=G02-04  
RESULT=EVIDENCE_RELATED  
GATE_MATRIX_FLIP=0  
GATE_MATRIX=NOT_RUN  
PROMOTE=0  
TIP_CLIMB=HOLD  
CROSS_SHA_CREDIT=0  
INVENT_PASS=0  
MATCH_PASS=0  
CLOSED=0  

## Mission

Close V_1 FP16 bucket via ATTN_NORM_1@dim1072 bitexact (NOT FFN_DOWN-only).  
Do not conflate with ATTN_PRE_O@pos1 FA CLOSED on 1CAEA762 (R64) under TOL 1e-6.

## Controlling (unchanged)

EXE_SHA256=`D282E57C97EB08938E122128F47798A7E2E76F8DED528C63A6E907C0266E2F2D`  
maxAbs_ATTN_PRE_O_1=`1.192093e-07`  
maxULP_f16=`1` @ idx59  
TIP_EXE_SHA256=`6754616E…` RO  

## Attempt (clean host FFN_DOWN under FORCE)

EXE_SHA256_ATTEMPT=`346859F257B6FF46C400DC9CCF5A3D8BFEF49E380B231E14F6007E388A8D13D9`  
PIN=`pin/rawr_attn_norm1_dim1072.exe` (remeasure dump later overwritten by reject arms)  
PATCH=`FORCE` → host Q6 FFN_DOWN by default + `memset` before `y[r]+=` GEMV; attn_v stays SPV; Q4 gate/up stays SPV (`PARITY=0`).  
Build: vulkan_fwd_* only against HEAD Deep2Engine (no dirty MARS).  

| Site | vs REF | note |
|------|--------|------|
| ACT maxAbs | 1.19e-07 | baseline SPV was 7.45e-08 |
| FD maxAbs | 2.24e-08 | baseline SPV 3.35e-08; [1072]d=-1.86e-08 |
| AN maxAbs | 2.38e-07 | baseline 7.15e-07; [1072]d=-1.79e-07 |
| V_1[59] | still f16=0862 (lo) | need≈+1.83e-09 to bnd; maxULP_f16=1 |
| ATTN_PRE_O_1 | maxAbs=1.192093e-07 | n_rel_gt=8; identical f16 PRE vs baseline |

CLOSED=0 (maxULP_f16=1; not within site TOL without inventing class TOL).

## Rejects this turn

1. `RAWRXD_Q6_HOST_FFN_DOWN` opt-in alone (B56FD8D3) — prior worker; contaminated ACT/AN0.  
2. Host Q4 gate/up + host FFN_DOWN (`PARITY=1`) — FD maxAbs≈7.5e-5; maxULP huge.  
3. `RAWRXD_RMSNORM_F32_SUM=1` (llama REF AN matches f32 sumSq) — global f32 sum regresses FFN_DOWN≈7.5e-5 (same class as 51e89df). Keep double sumSq default.  

## Offline isolate (PROMOTE=0)

- OWNER confirmed: AN[1072] is top V59 contributor from ANΔ; `L0=FIN+FD`; nudge `L0[1072]→REF` ⇒ `AN[1072]` bitexact REF.  
- Host Q6×Q8 on dump ACT is closer to REF FD than SPV (~1 ULP), but live cascade still leaves V59 1 ULP low.  
- `dumpFIN+REF_FD` is ~0.4e-9 below bnd on host-V; live SPV-V is higher — REF FD would likely flip live, but product FD not REF-bitexact yet (ACT residual).  

## NEXT

`NEXT_GATE=ATTN_NORM_1_ACT_FFN_DOWN_BITEXACT` — need ACT closer to REF so host/SPV FFN_DOWN lands REF side without Q4-host under FORCE.  
Do not invent MATCH/PASS. GATE_MATRIX stays NOT_RUN.  
PROMOTE=0 TIP_CLIMB=HOLD  
END  
