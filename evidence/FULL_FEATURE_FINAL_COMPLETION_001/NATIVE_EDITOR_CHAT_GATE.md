# NATIVE_EDITOR_CHAT_GATE — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:12:30Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
CANDIDATE_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
CANDIDATE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
TIP_CONFIG=RelWithDebInfo
FROZEN_A4F_UNTOUCHED=1
HARNESS=FULL_FEATURE_ONESHOT_001\harness\chat_ctrl_enter_verify.ps1
RECEIPT=artifacts\CHAT_CTRL_ENTER_RECEIPT.txt
RUNLOG=artifacts\chat_ctrl_enter_run_20261109-051150.txt
RUNTIME=candidates\tip_final_integ_002\chat_runtime.log
SAME_SHA_AS_EXT_LOAD=1
```

## AIM keyboard matrix (measured)

| Assertion | Result | Evidence |
|-----------|--------|----------|
| ENTER=NEWLINE | **PASS** | text retained + CR/LF present |
| SHIFT_ENTER=NEWLINE | **PASS** | same |
| CTRL_ENTER=SEND | **PASS** | exactly one `CHAT_SEND_ATTEMPT`; input cleared |
| SEND_BUTTON=SEND | **PASS** | one attempt via WM_COMMAND |
| EMPTY_MESSAGE=NO_SEND | **PASS** | `CHAT_SEND_REJECTED blank=1` |
| DUPLICATE_SEND=PREVENTED | **PASS** | held KEYDOWN repeats → one attempt |
| MULTILINE_UNICODE | **PASS** | CJK `你好` + Latin `é`/`cafe` + newline preserved |

```
CHAT_CTRL_ENTER_SEND=PASS
PASS_COUNT=7/7
AIM_SEND_PATH=PASS
UNICODE_CJK_CHAT_INPUT=PASS
EDITOR_FULL_MATRIX=NOT_RUN
```

## Repair note

`Win32IDE_lifecycle.cpp` Ctrl detection matched Core: `GetKeyState || GetAsyncKeyState` so SendInput Ctrl+Enter is visible to the AIM filter. Harness also requires no foreground thief (AMD Bug Report Tool killed during measure).

```
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## EXACTLY_ONCE correlation (delta — does NOT reopen sealed 7/7)

ASOF_LOCAL=2026-11-09T11:08-05
EXACTLY_ONCE=NOT_VERIFIED
SEALED_AIM_7_7=UNCHANGED
PROMOTE=0
MATURITY_HELD=82

| Mode | SHA under test | INPUT | DISPATCH | BACKEND_START | RESPONSE_END | USER/ASST INSERT | Multi-block under RXD_ONCE_* | Status |
|------|----------------|-------|----------|---------------|--------------|------------------|------------------------------|--------|
| button | `7B3C0ECB46A2AF063D626057111B0EF6730607AC839B40A805A121ABF1756655` (instrumented rebuild; ≠ CC79) | 1 | 1 | 1 | 0 | 1 / 0 | 0 (AI_BLOCKS_DELTA=0) | NOT_VERIFIED (timeout incomplete) |
| ctrl_enter | `CC79F6CD…A22940C4` (controlling tip; legacy tags) | n/a (pre-tag) | n/a | 1 (`request_started`) | 0 | 0 / 0 | 0 | NOT_VERIFIED (process_died_after_single_attempt; ATTEMPT=1) |

Evidence: `artifacts\CHAT_EXACTLY_ONCE_001\` (SOURCE_AUDIT.md; runs\button_20261109-101812\; runs\ctrl_enter_cc79_20261109-110745\).
Prior multi-AI-block / dispatch 1+2 observations remain consistent with multi-axis harness sequencing, not one opaque click→N dispatches.
Tip_005 `27E2263E…` and CC79 package binaries were not overwritten.
