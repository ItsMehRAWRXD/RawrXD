# G02-08 RELATED (≠ CERT PASS) — STREAM ENTER via PUMP_SKIP+ODR

| Field | Value |
|-------|-------|
| GATE_ID | G02-08 (near G04-01) |
| RESULT | RELATED |
| LABEL | private_cand_stream_enter_pump_odr_r80 |
| GIT_SHA | (this commit) / work/v0-first-divergence |
| EXE_SHA256 (controlling llama32) | CC18976E80B568E70222F9A181608872F2A36A3829F3DCCF886779D8D1BB0944 |
| TIP_SHA256 | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| TIP_STILL_6754 | 1 |
| CROSS_SHA_CREDIT | 0 |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| INVENT_PASS | 0 |
| COMMAND | run_ide_mf_qdim084_llama32.ps1 |
| TIMESTAMP | 2026-11-14T00:03:51-05:00 (controlling) |
| REVIEWER | agent_stream_enter_pump_r80 |

## Diagnosis

R73/R79 closed bad_alloc; residual **0xC0000005 READ VA=-1** after
`RXOW DECODE_STEP0` before `GENERATE_STREAM_ENTER`.

Root: stale `Deep2IDEIntegration.cpp.obj` owned `RunDecodeStream` under
`/FORCE:MULTIPLE` (LNK4006 ignored late `ProductRunDecode`) so
`SCOREBOARD_PUMP_SKIP` never executed. Pump/eng-pin class poisoned stream
prep (lease≈-1 / scoreboard).

## Fix landed (minimal, tip RO)

| Piece | Path |
|-------|------|
| SCOREBOARD_PUMP_SKIP default | `lavapath/ProductRunDecode.cpp` |
| Sole decode ODR | recompile `Deep2IDEIntegration` → RunDecodeStream UNDEF |
| Lease wild guard + crumbs | `Deep2Engine.cpp` generateStream post-config |
| Remasure expect | `run_ide_mf_qdim084_llama32.ps1` |

## Measure (fail-closed)

### Controlling (CC18976E) — ENTER closed on private llama32
- OPEN=1 · authPASS=1 · OPEN_SEH=0 · MARS_KEEP_GPU_PIN=1
- SCOREBOARD_PUMP_SKIP=1 · DECODE_ENG_PIN present
- GENERATE_STREAM_ENTER=1 · TOK=2 · INFER_STREAM_SEH=0 · EXIT=0
- TIP_STILL_6754=1 · CROSS_SHA_CREDIT=0 (gemma B8E5 TOK=8 not credited)

## Notes
- Controllers tip 6754616E RO (not overwritten).
- Peer board `BR_STREAM_ENTER_TOK_R80` (3792BAA7 greedy/embd) ≠ this PUMP ODR seal.
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `INVENT_PASS=0` · `RELATED ≠ CERT PASS`
