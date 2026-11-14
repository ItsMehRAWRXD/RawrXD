# Experimental inference backends — disposition matrix

`PROMOTE=0` · `CERTIFIED=0` · `TIP_CLIMB=HOLD` · `ENTERPRISE=0/128` · `INVENT_PASS=0` · `CROSS_SHA_CREDIT=0`

Tip EXE SHA256 `4743825156D9B012EDBB4F28F8249F2730A6B816BD6538B1FA82BCEA8754633D`  
(prior CEBA0DE4 / 7C9680CB / 340E56D7 held; no cross-SHA credit)

| Backend | Gate / flag | Disposition | Evidence | Owner / residual |
|--------|-------------|-------------|----------|------------------|
| Experimental SSM / Mamba2 | `RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1` | **SEALED** EXPERIMENTAL E2E (≠ SSM-CERT-001) | `G3_E_SSM_EXPERIMENTAL_FINISH_001` + AUTH/E2E_001–003; tip remasure TOK=8 REAL_FORWARD=1 IDENTITY=0 SSM_REAL=378; `PROVENANCE_MISMATCH` residual honest; PRODUCT_PASS=1 CLEAN_EXIT=1 | Stabilize provenance bind; numeric parity vs CERT held OPEN; `PROMOTE=0` |
| Dead branch FFN_ONLY IDENTITY | `ALLOW && false` removed | **SEALED** | `Deep2Engine.cpp` always `computeFFN` on FFN-only; SSM compute remains `computeSSM` under auth | — |
| Nemotron SSM SCAN opt-in | `RAWRXD_DEEP2_NEMOTRON_SSM_SCAN=1` | **SEALED** opt-in (default OFF) | `NemotronHSsmExperimental.hpp`; E2E_002 note SCAN poisoned when forced | Keep default OFF |
| Q6K Vulkan SPV product default | unforced (no FORCE_HOST) | **SEALED** RELATED | tip remasure HOST_HITS=0 TOK=8 COHERENT=`Yes, 2 + 2 =` PATH=SINGLE_GPU; also `BR_CLI_Q6K_R105_PRODUCT_DEFAULT` / POST_Q6K | Multifamily HOLD |
| Q6K SPV ↔ host numeric | independent oracle | **SEALED** RELATED_PARITY_OK | remasure maxAbs=1.86e-9 maxULP=640 GATE=PARITY_OK; `BR_CLI_Q6K_R105_SPV_NUMERIC`; host fallback ≠ SPV cert | — |
| Ornith hybrid llama REF_LOAD | qwen35moe hybrid schedule | **SEALED** PASS (no fabricate) | `deep2_ornith_hybrid_load_r105` AFTER LOAD=PASS CTX/DECODE/GEN=8; `BR_ORNITH_HYBRID_LOAD_R105`; L40 ABSENT_NOT_RENAME | — |
| Ornith Deep2 MoE+SSM tip | auth=1 tip EXE | **OPEN** FAIL | tip `runs/ornith_ssmauth` SSM_ENTER×30 MAMBA_ARM=0 GEO_OR_BUF; FORWARD_FAIL explode; TOK=0 | `DEEP2_ORNITH_PROD_DECODE` / arm Ornith SSM geo |
| Ornith Deep2 prior pin | R99 / R103_moe | **SEALED** PARTIAL RELATED | R99 TOK=8; R104 L3 ULP_CLOSED vs f32; SEMANTIC OPEN (`ORNITH_SEMANTIC_BEYOND_L3_001`) | SEMANTIC close |
| Laguna REAP tip | non-SSM | **SEALED** RELATED (prior) | `BR_REAP_LAGUNA_TIP_PASS_R105` CEBA0DE4 TOK=8 LAYER_NAN=0; tip 4743 not re-credited | Fair H2H OPEN |
| Fair H2H matrix | equal tok budget | **OPEN** | `REAP_STRATA_FAIR_H2H_001` | identical num_predict=32 N≥3 |
| GPU Multimap-only | `RAWRXD_GPU_POLICY=MULTI` | **N/A** product policy | TinyLlama MULTI HOST_HITS=0 held on CEBA; not experimental backend | — |
| Medusa / trampoline | stack mech | **N/A** | product LIVE_PATH mechs; not gated experimental inference backend finish | — |
| SSM-CERT-001 refuse | no ALLOW flag | **SEALED** held | `G3_E_SSM_CERT_001` DO_NOT_REWRITE | — |

## Closed this finish
1. Experimental SSM compute path under auth (dead IDENTITY branch removed; Nemotron Mamba2 tip remasure TOK/SEH/PROD_DECODE witnesses).
2. Q6K unforced product default remasured on tip EXE.
3. Independent SPV↔host numeric remasured PARITY_OK.
4. Ornith llama hybrid REF_LOAD (absorbed from R105 hybrid board; no fabricate).

## Remains OPEN
1. Ornith Deep2 tip semantic / FORWARD_FAIL (GEO_OR_BUF; explode).
2. Ornith Deep2 PROD_DECODE / heap residual (BEYOND_L3).
3. Fair H2H competitive matrix.
4. Q6K multifamily expand.
5. `PROVENANCE_MISMATCH` residual on experimental + product CLI receipts.

## Law held
`PROMOTE=0` · `EXPERIMENTAL_NEQ_SSM_CERTIFIED_IMPL` · `METHOD_C_COMPLETE≠enterprise` · `GATE_STOP=1` · no `blk.40.ssm_conv1d.weight` fabricate
