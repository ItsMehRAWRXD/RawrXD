# G02-08 RELATED (≠ CERT PASS) — TIP_ABSORB_AUTH_HOLD R82

| Field | Value |
|-------|-------|
| GATE_ID | G02-08 (near G06-06) |
| RESULT | RELATED |
| LABEL | tip_absorb_auth_hold_r82_private_pump_odr |
| GIT_SHA | (this commit) / work/v0-first-divergence |
| EXE_SHA256 | F44D053D90308097F92209A5F9B3043553AC7429265B64F06E5774228B5A6D4E |
| TIP_SHA256 | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| TIP_STILL_6754 | 1 |
| CROSS_SHA_CREDIT | 0 |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| INVENT_PASS | 0 |
| PCT_HELD | CLI67/GUI48/OVERALL48 |
| COMMAND | run_ide_mf_qdim084_tip_absorb_r82_llama32.ps1 |
| TIMESTAMP | 2026-11-14T00:19:43-05:00 |
| REVIEWER | agent_tip_absorb_auth_hold_r82 |

## Absorb path (fail-closed)

Rebuild private cand from current sources with SCOREBOARD_PUMP_SKIP default
(ProductRunDecode sole RunDecodeStream; Deep2IDEIntegration RunDecodeStream=UNDEF).
Tip `bin/RawrXD-Win32IDE.exe` SHA 6754616E RO (pre/post). No tip climb.

| Piece | Path |
|-------|------|
| SCOREBOARD_PUMP_SKIP default | `lavapath/ProductRunDecode.cpp` |
| IDEIntegration ODR | recompile `Deep2IDEIntegration.cpp` → UNDEF RunDecodeStream |
| Private link | `clean_link/obj084_mars_keep/rebuild_tip_absorb_r82.bat` |
| Remasure | `gpu/run_ide_mf_qdim084_tip_absorb_r82_llama32.ps1` |

## Measure

- OPEN=1 · OPEN_SEH=0 · CRITICAL=PASS · KEEP_GPU=1
- SCOREBOARD_PUMP_SKIP=1 · DECODE_ENG_PIN present
- GENERATE_STREAM_ENTER=1 · TOK=2 · INFER_STREAM_SEH=0 · EXIT=0
- AUTH_HOLD=1 · TIP_ABSORB=0 · REJECT_FORCE_ABSORB=1
- TIP_STILL_6754=1 · CROSS_SHA_CREDIT=0 (≠ CC18976E / 3792BAA7 / B8E5)

## Notes

- Board `BR_TIP_ABSORB_AUTH_HOLD_R82` · RELATED_NOT_PASS
- Peer durable 3792BAA7 / pump CC18976E not credited as this EXE
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · PCT unchanged · ≠ CERT PASS
- NEXT_OWNER=ATTN_PRE_O_1_POS1
