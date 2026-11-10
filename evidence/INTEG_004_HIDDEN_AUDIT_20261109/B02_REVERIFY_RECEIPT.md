# B02_REVERIFY_RECEIPT — INTEG_004 cross-subsystem reverify

```text
ASOF_UTC=2026-11-09T13:28:30Z
GATE_ID=B02
REGISTER_TITLE=INTEG_004 cross-subsystem incomplete (NEEDS_REVERIFY)
CHOSEN_IMAGE_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
CHOSEN_IMAGE_ROLE=RECONCILED_CANDIDATE tip_final_integ_004
SEALED_47451F24_EXE=ABSENT
NO_INHERIT_47451=1
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
B02_DISPOSITION=FAIL
MATRIX_SEALED=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
```

## Required proof (register)

SHA-specific matrix on **one** image: Extension, Chat, Terminal, Output, Debug-headless, Problems populate + **actual** caret navigation.

## Measured matrix (`27E2263E…`)

| Subsystem | Result | Notes |
|-----------|--------|-------|
| Extension | PASS | FORCE_KILL=0 (see B20) |
| Chat | FAIL | HWND present; stream/stop/clear NOT_RUN |
| Terminal | FAIL | `--term-smoke` FORCE_KILL=1 |
| Output | PASS | GUI_OUTPUT_PANEL_E2E=PASS |
| Debug-headless | PASS | VERIFY_RC=0 SESSION_REAL=1 |
| Problems populate | PASS | items=3 |
| B12 caret nav | FAIL | POSTED_NM_DBLCLK only |

```text
B02_CLOSED=0
B02_DISPOSITION=FAIL
REMAINING=CHAT,TERMINAL,B12_CARET
ARTIFACT=PHASE_A_SHA_MATRIX_27E2263E.md
```
