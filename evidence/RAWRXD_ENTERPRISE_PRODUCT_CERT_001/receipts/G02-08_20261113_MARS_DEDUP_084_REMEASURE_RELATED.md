# G02-08 RELATED (≠ CERT PASS) — MARS dedup private 084 remasure

| Field | Value |
|-------|-------|
| GATE_ID | G02-08 (near G04-01) |
| RESULT | RELATED |
| LABEL | private_cand_mars_dedup_084 |
| GIT_SHA | a2f8744299 / work/v0-first-divergence (≥ b61f03972e) |
| EXE_SHA256 (llama32 / qdim084) | 4F76D501D2399315AE1A7936D96159FFD741E5ED8151990F12323440265D5890 |
| EXE_SHA256 (gemma3 / tip_land avfix084) | 1108BF01B5A3F0FB142479812E69C81600E955DE64E86E1FD3428F146142EDCA |
| TIP_SHA256 | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| TIP_STILL_6754 | 1 |
| CROSS_SHA_CREDIT | 0 |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| INVENT_PASS | 0 |
| COMMAND | run_ide_mf_qdim084_llama32.ps1 / run_ide_mf_tipland_avfix084_gemma3.ps1 |
| TIMESTAMP | 2026-11-13T22:42:12-05:00 .. 22:43:31-05:00 |
| REVIEWER | agent_mars_dedup_084_remeasure |

## Measure (fail-closed)

### llama32 (qdim084 lineage)
- Witness: `gpu/ide_mf_qdim084_llama32_4F76D501D2399315_20261113_224212.meta.txt`
- TOK=0 · OPEN_SEH=0 · INFER_STREAM_SEH=0 · DUP_TOKEN_EMBD_WARN=0 · GENERATE_STREAM_ENTER=0
- MARS_KEEP_GPU_PIN=1 · PRODUCT_OPEN_CRITICAL_TENSORS=PASS
- PRODUCT_OPEN_PASS=0 · OPEN_BODY_GATE openRc=0 authPASS=0 · SESSION_EXIT ok=0 stage=POST_LOAD
- TOKEN_SURVIVED=0

### gemma3 (tip_land avfix084 lineage)
- Witness: `gpu/ide_mf_tipland_avfix084_gemma3_1108BF01B5A3F0FB_20261113_224321.meta.txt`
- TOK=0 · OPEN_SEH=0 · INFER_STREAM_SEH=0 · DUP_TOKEN_EMBD_WARN=0 · GENERATE_STREAM_ENTER=0
- MARS_KEEP_GPU_PIN=1 · PRODUCT_OPEN_CRITICAL_TENSORS=PASS
- PRODUCT_OPEN_PASS=0 · OPEN_BODY_GATE openRc=0 authPASS=0
- TOKEN_SURVIVED=0 · Prior F5997910 had INFER_STREAM_SEH=1; this cand STREAM_SEH=0 but OPEN not durable

## Notes
- Controllers tip 6754616E RO (not overwritten).
- SOURCE_WIRED: `placeAllModelTensorsMARS` dedup (b61f) + keep path (85483→narrowed token_embd-exact in b49e).
- Broad keepPinnedOnGpu private cand 1EFF8608/4F76D501 → POST_LOAD OPEN_FAIL (authPASS=0); ≠ PASS.
- Private EXEs under `GUI_TOP25_VALUATION_001/clean_link/` only.
