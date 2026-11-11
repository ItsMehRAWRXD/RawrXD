# CHAT_TRANSCRIPT_17_RECONCILE

ASOF_UTC=2026-11-09T11:30:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

## Corrected law (do not regress)

```
17_TRANSCRIPT_LINES ≠ 17_AIM_SUBMISSIONS
TRANSCRIPT_TEXT_CAPTURE = Observed accumulated history only
AIM_HARNESS_SEALED = 1/1/1 send attempts (Ctrl+Enter / Hold / Button)
SEALED_TIP_2CB03699_SUPPORTS = 3 CHAT_SEND_ATTEMPT + 1 REJECT — NOT exactly-once
DISPATCH_ID_PER_MESSAGE = ABSENT
EXACTLY_ONCE_DELIVERY = NOT_VERIFIED
BACKEND_RESPONSE = NOT_VERIFIED
CHAT_FULL_ACCEPTANCE = NOT_VERIFIED
BUILD_OUTPUT_HWND = FAIL when SAMPLE contains "> User:" chat history
PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0
```

## Reported probe inventory (UI history — supporting only)

| Probe | Count |
|------:|------:|
| test | 1 |
| button-probe | 5 |
| ctrl-enter-probe | 8 |
| hold-probe | 3 |
| **Total visible rows** | **17** |

These accumulate across launches into the same workspace session. They are **not** one atomic AIM run of 17 accepted Sends.

## Sealed AIM harness (separate — do not conflate)

| Artifact | Value |
|----------|-------|
| Tip | `2CB036995C8F8D371BCACEA575CE3E4BECEA0CBE792BAA67508C702A79AA0DF7` |
| Receipt | `artifacts\CHAT_CTRL_ENTER_RECEIPT.txt` / tip005 copy |
| Runtime | `candidates\tip_chat_ctrl_enter_002\chat_runtime.log` |
| NEW_ATTEMPTS | 1 |
| HELD_ATTEMPTS | 1 |
| BUTTON_ATTEMPTS | 1 |
| REJECT (blank) | 1 |
| request_id | 1 only (`request_started`) |
| Per-message dispatch IDs | **ABSENT** |

```
SEALED_RUN_SEND_ATTEMPTS=3
TRANSCRIPT_17_VS_ATTEMPTS=NO_1_1_MAP
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
BACKEND_RESPONSE=NOT_VERIFIED
```

## HWND contamination (tip_final_005 CC79)

`TIP005_OUTPUT_PROBLEMS_HWND_RECEIPT.txt` / `tip005_hwnd_console.txt`:
`BUILD_LINE_SAMPLE` / Problems SAMPLE contain `> User: …` chat lines.
Root cause: product Build channel used HWND id **1204**, colliding with `IDC_COPILOT_SEND_BTN`; harness `SampleVisibleEdit` then attributed longest visible edit (chat) as Build.

```
OUTPUT_HWND=FAIL
ACTIVE_REPAIR=TIP005_HWND
EXACTLY_ONCE_AFTER_HWND_REPAIR_ONLY=1
```

## Authority

```
PRESERVE_SEALED_AIM=1
NO_LINEAGE_PROMOTION=1
EA5D_CC79_ACCEPTANCE_UNCHANGED=1
PROMOTE=0
```
