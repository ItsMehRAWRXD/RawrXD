# CHAT_DISPATCH_TRANSCRIPT_LAW

ASOF_UTC=2026-11-09T13:16:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CONTROLLING_TIP=CC79

## Artifact class

`candidates\tip_dispatch_corr_001\visible_transcript_sample.txt` (and similar probe transcripts) are **chat dispatch test transcripts**, **not** the hidden-gap defect register and **not** Ctrl+Enter / Send-button acceptance.

```
TRANSCRIPT_CLASS=MODEL_RESPONSE_DELIVERY_SUPPORTING
CTRL_ENTER_CORRECTNESS_FROM_TRANSCRIPT=0
INTEGRATED_PASS_FROM_TRANSCRIPT=0
MODEL_TEXT_NE_UI_PROBE_PASS=1
```

## Observations → required verification

| Observation | Gap / required verification | Status |
|-------------|------------------------------|--------|
| `button-probe`, `ctrl-enter-probe`, `hold-probe` receive responses | Dispatch reaches a responding model; **input event correctness unverified** | OPEN |
| Dispatch IDs restart across transcript sections | Record **session_id / run_id** to distinguish normal resets vs duplicate dispatch | OPEN |
| Some entries have no response | Classify cancelled / interrupted / failed / pending | OPEN |
| Model repeats “BigDaddyG Productivity Mode” + formatting instructions | Inspect effective system prompt, chat template, session history | OPEN (quality; ≠ input PASS) |
| Model invents commands/packages for probe labels | Responses **cannot** evidence UI probes passed | LAW |
| Emoji as `ðŸš€` / `ðŸ˜‰` | UTF-8 decode across capture, display, transcript export | OPEN |

## Bound receipts (fail-closed)

Prior AIM 7/7 on CC79 (`NATIVE_EDITOR_CHAT_GATE`) is **SHA-scoped** and must not be inherited onto tip_hwnd_repair / tip_dispatch_corr without remeasure.

Dispatch_id correlation on `30B9BA78…` (`DISPATCH_ID_CORRELATION_RECEIPT.txt`): RUNTIME_AND_TRANSCRIPT_HIT with 1 ARMED / 2 BUSY — **correlation ≠ input-event PASS**; `EXACTLY_ONCE_DELIVERY=NOT_VERIFIED`; `CHAT_FULL_ACCEPTANCE=NOT_VERIFIED`. Sealed complete: `artifacts\DISPATCH_ID_CORRELATION_COMPLETE.md` (worker 85a3617b).

Visible `button-probe` / `ctrl-enter-probe` lines in the same tip’s transcript sample remain **delivery support only** under this law.

## Next acceptance gate

See `INPUT_EVENT_DISPATCH_GATE.md` (instrumented button/keyboard events + SHA/session/run bind).
