# G02-08 RELATED (≠ CERT PASS) — MARS 084 authPASS remasure

| Field | Value |
|-------|-------|
| GATE_ID | G02-08 (near G04-01) |
| RESULT | RELATED |
| LABEL | private_cand_mars_084_authpass_fix |
| GIT_SHA | (this commit) / work/v0-first-divergence |
| EXE_SHA256 (llama32 / qdim084) | 9181073D854DEADB404626344DC5909EFB411B456A4D20E1933BCBB63B825D0B |
| EXE_SHA256 (gemma3 / tip_land avfix084) | CC621549822A766383B01FF4839BD2570DBCC2806D87493E04A25C794DDC0AA7 |
| TIP_SHA256 | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| TIP_STILL_6754 | 1 |
| CROSS_SHA_CREDIT | 0 |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| INVENT_PASS | 0 |
| COMMAND | run_ide_mf_qdim084_llama32.ps1 / run_ide_mf_tipland_avfix084_gemma3.ps1 |
| TIMESTAMP | 2026-11-13T23:10:25-05:00 .. 23:09:36-05:00 |
| REVIEWER | agent_mars_084_authpass |

## Diagnosis (authPASS=0 @ POST_LOAD)

Prior 4F76D501 / 1108BF01: `OPEN_BODY_GATE openRc=0 … authPASS=0` with
`RAW_RUN_OPEN=FAIL stage=POST_LOAD gguf=0 tok=1`.

Root causes (fail-closed):

1. `ProductRuntime.auth.PASS` is only set after `rawr_run::OpenSession` succeeds.
   POST_LOAD `gguf=0` (`modelWeights.loaded` cleared / unread) aborted before
   `sessionAuthority()` copy → `AuthorityComplete()=0` even when load sealed
   `AUTHORITY_LADDER=SESSION_SEAL_ONLY`.
2. Private link COMDAT: `sessionAuthorityPass` / `isModelLoaded` were won by
   stale `product_deep2_infer_seh.cpp.obj` (map). Eng now emits **strong**
   out-of-line accessors; LNK4006 ignores SEH duplicates.
3. `repairModelLoadedFromRoots()` restores `loaded` when roots live after enhance.

## Fix (minimal, tip RO)

- `Deep2Engine.h/.cpp`: out-of-line `isModelLoaded` / `getModelWeights` /
  `sessionAuthority` / `sessionAuthorityPass` + `repairModelLoadedFromRoots`
- `RawrRunSession.hpp` + `RawrRunSession_Body.cpp`: POST_LOAD calls Eng repair
- Link order: Eng.obj before `product_deep2_infer_seh`
- Remasure env: `DEEP2_MARS=1`, `RAWRXD_ENHANCE_SKIP=torus,plasma,chamber,sov,medusa,nu,warmup`
  (avoids llama OPEN_SEH 0xE06D7363 post-sov class)

## Measure (fail-closed)

### llama32 (qdim084)
- Witness: `gpu/ide_mf_qdim084_llama32_9181073D854DEADB_20261113_231025.meta.txt`
- OPEN_BODY_GATE openRc=1 loaded=1 tens=1 **authPASS=1**
- **PRODUCT_OPEN_PASS=1** · OPEN_SEH=0 · INFER_STREAM_SEH=1 (0xE06D7363)
- MARS_KEEP_GPU_PIN=1 · PRODUCT_OPEN_CRITICAL_TENSORS=PASS
- TOK=0 · GENERATE_STREAM_ENTER=0 · TOKEN_SURVIVED=0 · EXIT=0

### gemma3 (tip_land avfix084)
- Witness: `gpu/ide_mf_tipland_avfix084_gemma3_CC621549822A7663_20261113_230929.meta.txt`
  (+ err OPEN facts)
- OPEN_BODY_GATE openRc=1 loaded=1 tens=1 **authPASS=1**
- **PRODUCT_OPEN_PASS=1** · OPEN_SEH=0 · MARS_KEEP_GPU_PIN=1
- TOK=0 · GENERATE_STREAM_ENTER=0 · PROCESS_EXIT=NULL (stream not durable)
- Prior same-SHA with enhance-skip: STREAM_SEH=1 EXIT=0 (KEEP=0)

## Notes
- Controllers tip 6754616E RO (not overwritten).
- authPASS/OPEN_PASS closed vs 084 remasure residual; STREAM/TOK still open.
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `INVENT_PASS=0` · `CROSS_SHA_CREDIT=0`
- NEXT: STREAM_SEH 0xE06D7363 / GENERATE_STREAM_ENTER / TOK>0 (≠ tip absorb)
