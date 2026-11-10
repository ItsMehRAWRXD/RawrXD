# CHAT_EXACTLY_ONCE_001 — Disposition

ASOF_LOCAL=2026-11-09T11:08-05
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY_HELD=82
INVENT_PASS=0
EXACTLY_ONCE=NOT_VERIFIED

## Verdict

Fail-closed: **EXACTLY_ONCE=NOT_VERIFIED** (not PASS). Full conjunction
`1 click → 1 DISPATCH → 1 BACKEND → 1 RESPONSE_END → 1 user+assistant transcript pair`
was **not** completed on any single measured run (response incomplete / process death).

No evidence of **duplicate execution** under opaque `RXD_ONCE_*` tokens in these runs.
Multi-block AI symptom **did not reproduce** (`MULTI_BLOCK_REPRODUCED=0`, `AI_BLOCKS_DELTA=0`).

## Correlation table

| Mode | SHA | INPUT | DISPATCH | BACKEND_START | RESPONSE_END | USER_INS | ASST_INS | AI_BLOCKS_DELTA | EXACTLY_ONCE |
|------|-----|-------|----------|---------------|--------------|----------|----------|-----------------|--------------|
| button | `7B3C0ECB…F1756655` instrumented | 1 | 1 | 1 | 0 | 1 | 0 | 0 | NOT_VERIFIED |
| ctrl_enter | `CC79F6CD…A22940C4` CC79 | 0* | 0* | 1† | 0 | 0 | 0 | 0 | NOT_VERIFIED |

\* CC79 predates `INPUT_EVENT source=` / `DISPATCH_ID id=` tags; send proven via `CHAT_SEND_ATTEMPT bytes=41` once.  
† Legacy `request_started request_id=1` (counted as backend start). Process died before armed/response-end.

## Root cause notes

| Finding | Classification |
|---------|----------------|
| Button: 1 INPUT → 1 DISPATCH → 1 BACKEND_START → RESPONSE_START; stream incomplete within wait | incomplete_chain / timeout — **not** double handler |
| Ctrl+Enter on CC79: one CHAT_SEND_ATTEMPT then PROCESS_DIED | process_died_after_single_attempt |
| Prior “dispatch 1 and 2” with button-probe | harness multi-axis sequencing (unicode/short/button), not one-click→two-dispatch |
| PowerShell leak into chat | agentic_bridge mirror tracer SOURCE_WIRED (`TRANSCRIPT_INSERT role=agent_mirror`); not observed in these RXD_ONCE runs (`POWERSHELL_HINT_COUNT=0`) |

## Frozen tips

```
CC79=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4 UNTOUCHED=1
TIP_005=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC UNTOUCHED=1
A4F_UNTOUCHED=1
SEALED_G_CHAT_7_7=UNCHANGED
```

## Paths

- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\SOURCE_AUDIT.md`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\DISPOSITION.md`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\runs\button_20261109-101812\RECEIPT.txt`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\runs\button_20261109-101812\delta_chat_runtime.log`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\runs\ctrl_enter_cc79_20261109-110745\RECEIPT.txt`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001\runs\ctrl_enter_cc79_20261109-110745\delta_chat_runtime.log`
- Gate note delta: `NATIVE_EDITOR_CHAT_GATE.md` (EXACTLY_ONCE section; sealed 7/7 unchanged)
- Gap register: `MASTER_HIDDEN_GAP_REGISTER_001.md` row `G-CHAT-EXACTLY-ONCE`

## Next proof (not this disposition)

Instrument + survive full RESPONSE_END on one SHA (button and ctrl_enter separately); then re-evaluate EXACTLY_ONCE. Do not inherit PASS across SHA. Do not touch tip_005 / CC79 packages while measuring.
