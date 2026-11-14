# G02-08 RELATED (≠ CERT PASS) — STREAM after authPASS remasure

| Field | Value |
|-------|-------|
| GATE_ID | G02-08 (near G04-01) |
| RESULT | RELATED |
| LABEL | private_cand_stream_after_authpass_r73 |
| GIT_SHA | (this commit) / work/v0-first-divergence |
| EXE_SHA256 (controlling llama32) | 330ECC0A4194D29C385EF55EFAA1FA1397EC4D92A5DC3560AD15C18096CDA405 |
| TIP_SHA256 | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| TIP_STILL_6754 | 1 |
| CROSS_SHA_CREDIT | 0 |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| INVENT_PASS | 0 |
| COMMAND | run_ide_mf_qdim084_llama32.ps1 |
| TIMESTAMP | 2026-11-13T23:23:09-05:00 (controlling) |
| REVIEWER | agent_stream_after_authpass_r73 |

## Diagnosis

R72 closed authPASS/OPEN on 9181073D / CC621549. Residual STREAM:

1. **0xE06D7363 (MSVC C++ EH / bad_alloc)** after keepGPU pin when host
   commit is exhausted — CompressedKV/torus sized from GGUF ctx (131072)
   plus double residency (host weights + GPU place) under concurrent remasure.
2. After **KV_WORKING_SEQ_BOUND** + **ckv/nvme enhance-skip** + ProductRun
   catch: controlling **330ECC** reaches OPEN=1 authPASS=1 KEEP=1, then
   **0xC0000005 READ VA=-1** immediately after `RXOW DECODE_STEP0` and
   before `GENERATE_STREAM_ENTER` (scoreboard pump / eng-pin class).

## Fix landed (minimal, tip RO)

| Piece | Path |
|-------|------|
| KV working-seq bound | `Deep2Engine.cpp` enableAllEnhancements |
| keepGPU pin | `Deep2Engine.cpp` placeAllModelTensorsMARS |
| ToroidalKV catch | `Deep2Engine.cpp` enableToroidalKV |
| ProductRun catch | `lavapath/ProductRun.hpp` |
| Scoreboard pump skip | `lavapath/ProductRunDecode.cpp` (default skip) |
| Eng ODR accessors | `Deep2Engine.h/.cpp` out-of-line |
| InitFromPath ctx prefer | `RawrRunSession_Body.cpp` |
| Remasure env | `run_ide_mf_qdim084_llama32.ps1` |

## Measure (fail-closed)

### Controlling (330ECC) — bad_alloc cleared; ENTER residual
- OPEN_BODY / PRODUCT_OPEN_PASS path: **authPASS=1** · **OPEN_SEH=0**
- MARS_KEEP_GPU_PIN=1 · PRODUCT_OPEN_CRITICAL_TENSORS=PASS
- GENERATE_STREAM_ENTER=0 · TOK=0 · TOKEN_SURVIVED=0
- INFER_STREAM_SEH=1 CODE=0xC0000005 VA=FFFFFFFFFFFFFFFF
- EXIT=0 · TIP_STILL_6754=1

### Prior R72 residual (9181073D)
- OPEN=1 auth=1 · INFER_STREAM_SEH=1 CODE=0xE06D7363 · TOK=0 · ENTER=0

## Notes
- Controllers tip 6754616E RO (not overwritten).
- Later FORCE private links hit OPEN_SEH under engpin ODR churn — not credited.
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `INVENT_PASS=0` · `CROSS_SHA_CREDIT=0`
- NEXT: durable ENTER=1 TOK>0 SEH=0 with pump-skip+ODR without OPEN_SEH
