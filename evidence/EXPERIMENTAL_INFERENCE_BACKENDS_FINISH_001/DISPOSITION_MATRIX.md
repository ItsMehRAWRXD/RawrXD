# Experimental inference backends — disposition matrix

`PROMOTE=0` · `CERTIFIED=0` · `TIP_CLIMB=HOLD` · `ENTERPRISE=0/128` · `INVENT_PASS=0` · `CROSS_SHA_CREDIT=0`

Controlling tip EXE SHA256 `D029E0FF60F5708B19B53B2A4409AD23BFDF87EFF02E75A4359952E1FF63B42E`  
(prior CEBA0DE4 / 7C9680CB / 340E56D7 / 47438251 held; no cross-SHA credit)

| Backend | Gate / flag | Disposition | Evidence | Owner / residual |
|--------|-------------|-------------|----------|------------------|
| Experimental SSM / Mamba2 | `RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1` | **SEALED** EXPERIMENTAL E2E (≠ SSM-CERT-001) | `runs/nemotron_ssmauth.*` on D029; TOK=8 REAL_FORWARD=1 IDENTITY=0 SSM_REAL=378; PRODUCT_PASS=1; `PROVENANCE_MISMATCH` residual honest; also `G3_E_SSM_EXPERIMENTAL_*` | Stabilize provenance; numeric vs CERT OPEN; `PROMOTE=0` |
| Dead branch FFN_ONLY IDENTITY | `ALLOW && false` removed | **SEALED** | `Deep2Engine.cpp` always `computeFFN` on FFN-only; SSM compute remains `computeSSM` under auth | — |
| Nemotron SSM SCAN opt-in | `RAWRXD_DEEP2_NEMOTRON_SSM_SCAN=1` | **SEALED** opt-in (default OFF) | `NemotronHSsmExperimental.hpp`; E2E_002 SCAN poisoned when forced | Keep default OFF |
| Q6K Vulkan SPV product default | unforced (no FORCE_HOST) | **SEALED** RELATED | `runs/q6k_default_solo_d029.*` HOST_HITS=0 TOK=8 COHERENT=`Yes, 2 + 2 =` PATH=SINGLE_GPU; R103/R104 not reabsorbed | Multifamily HOLD |
| Q6K SPV ↔ host numeric | independent oracle | **SEALED** RELATED_PARITY_OK | `R105_Q6K_SPV_NUMERIC_001` + `runs/q6k_spv_host_parity` GATE=PARITY_OK maxAbs=1.86e-9; host fallback ≠ SPV cert | — |
| Ornith hybrid llama REF_LOAD | qwen35moe hybrid schedule | **SEALED** PASS (no fabricate) | `deep2_ornith_hybrid_load_r105` AFTER LOAD/CTX/DECODE/GEN=8; L40 ABSENT_NOT_RENAME cleared via probe | — |
| Ornith Deep2 MoE+SSM tip | auth=1 tip EXE | **OPEN** / **BLOCKED** | tip remasure: load OK; `SSM_MAMBA2_ARM=0 GEO_OR_BUF`; prior tip FORWARD_FAIL; R99 pin TOK=8 PARTIAL | `DEEP2_ORNITH_SSM_GEO` / SEMANTIC |
| Ornith Deep2 prior pin | R99 / R103_moe / R104 | **SEALED** PARTIAL RELATED | R99 TOK=8; R104 L3 ULP_CLOSED vs f32 held; SEMANTIC OPEN | SEMANTIC close |
| Laguna REAP tip | non-SSM | **SEALED** RELATED (prior) | prior boards; tip D029 not re-credited (CROSS_SHA=0) | Fair H2H OPEN |
| Fair H2H matrix | equal tok budget | **OPEN** | `REAP_STRATA_FAIR_H2H_001` | identical num_predict=32 N≥3 |
| GPU Multimap-only | `RAWRXD_GPU_POLICY=MULTI` | **N/A** product policy | TinyLlama MULTI HOST_HITS=0 held on CEBA; not experimental backend | — |
| Medusa / trampoline | stack mech | **N/A** | product LIVE_PATH mechs; not gated experimental inference backend finish | — |
| SSM-CERT-001 refuse | no ALLOW flag | **SEALED** held | `G3_E_SSM_CERT_001` DO_NOT_REWRITE | — |

## Closed this finish
1. Experimental SSM compute path under auth (dead IDENTITY branch removed; Nemotron Mamba2 tip remasure TOK/SEH/PROD_DECODE witnesses on D029).
2. Q6K unforced product default remasured on tip EXE D029 (HOST_HITS=0, coherent).
3. Independent SPV↔host numeric PARITY_OK (R105 numeric board).
4. Ornith llama hybrid REF_LOAD PASS without fabricating `blk.40.ssm_conv1d.weight`.

## Remains OPEN
1. Ornith Deep2 tip semantic / Mamba2 geo arm (`GEO_OR_BUF`).
2. Fair H2H competitive matrix.
3. Q6K multifamily expand.
4. `PROVENANCE_MISMATCH` residual on experimental + product CLI receipts.

## Law held
`PROMOTE=0` · `EXPERIMENTAL_NEQ_SSM_CERTIFIED_IMPL` · `METHOD_C_COMPLETE≠enterprise` · `GATE_STOP=1` · no `blk.40.ssm_conv1d.weight` fabricate
