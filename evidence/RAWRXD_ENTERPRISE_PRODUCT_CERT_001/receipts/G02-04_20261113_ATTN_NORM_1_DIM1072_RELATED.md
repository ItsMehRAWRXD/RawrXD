# G02-04 RELATED — ATTN_NORM_1@dim1072 ACT→FFN_DOWN bitexact (CLOSED)

GATE_ID=G02-04  
RESULT=EVIDENCE_RELATED  
GATE_MATRIX_FLIP=0  
GATE_MATRIX=NOT_RUN  
PROMOTE=0  
TIP_CLIMB=HOLD  
CROSS_SHA_CREDIT=0  
INVENT_PASS=0  
MATCH_PASS=0  
CLOSED=1  

## Mission

Close V_1 FP16 bucket via ATTN_NORM_1@dim1072 ACT→FFN_DOWN→ATTN_NORM product path  
(NOT FFN_DOWN-host under FORCE; NOT invented class TOL).  
CLOSED criterion: maxULP_f16=0 (met).  

## Controlling (this remasure)

EXE_SHA256=`F0A8018F21FC76A5818570135C1C5F63596571C10CCCD7FC38A1B133CFD1F4F7`  
PIN=`pin/rawr_attn_norm1_dim1072.exe`  
DUMP=`FIRST_DIVERGE_001/stage_dump_attn_norm1_dim1072`  
Q4K_SPV=`4548BCF1…` / 16868 (precise float-contract)  
ENV=`RAWRXD_FORCE_VULKAN_QUANT_GEMV=1` `RAWRXD_QUANT_HOST_Q8K_PARITY=0`  
  (product default: FORCE→SPV for Q4 square, Q4 gate/up, Q6 FFN_DOWN, Q6 attn_v)  

| Site | vs REF | note |
|------|--------|------|
| ACT maxAbs | 1.192093e-07 | UNDER prior site; Q8 int8 path sealed via precise SPV |
| FD maxAbs | 2.235174e-08 | [1072]d=-1.12e-08 |
| AN maxAbs | 2.384186e-07 | [1072]d=-5.96e-08 |
| V_1[59] | f16=0863 (hi) | need=-4.95e-10 (above bnd); maxULP_f16=0 |
| ATTN_PRE_O_1 | maxAbs=0 | BITEXACT; n_bucket=0 |

CLOSED=1 (maxULP_f16=0; PRE_O_1 float-bitexact). No TOL invent.

## Prior rejects (still reject)

1. Host Q6 FFN_DOWN under FORCE (346859F2 / 5408f09e) — V59 1 ULP lo (~1.83e-9).  
2. Host Q4 gate/up + FD (PARITY=1) — FD~7.5e-5.  
3. `RAWRXD_RMSNORM_F32_SUM=1` — FFN_DOWN~7.5e-5.  
4. Host Q4 square under FORCE (q4_attn_sq default) — poisons FD~7.5e-5 despite tight ACT.  

## Product policy landed

- `vulkan_fwd_quant_host.cpp` / `vulkan_fwd_q6k_host.cpp`: FORCE alone → SPV for  
  Q6 FFN_DOWN; Q4 square host opt-in only (`RAWRXD_Q4_HOST_ATTN=1`).  
- Precise Q4K SPV already active (`4548BCF1…`) for gate/up ACT Q8 boundary.  

## Prior controlling (superseded for this site)

EXE_SHA256_PRIOR_OPEN=`D282E57C97EB08938E122128F47798A7E2E76F8DED528C63A6E907C0266E2F2D`  
  maxULP_f16=1 @idx59 maxAbs_PRE=1.192093e-07  
ATTEMPT_HOST_FD=`346859F2…` CLOSED=0  

TIP_EXE_SHA256=`6754616E…` RO  
PROMOTE=0 TIP_CLIMB=HOLD  
GATE_MATRIX stays NOT_RUN (RELATED ≠ matrix PASS).  
BOARD=`BR_ATTN_NORM_BITEXACT_R75.txt`  
END  
