# CHAT_EXACTLY_ONCE_CORRELATE

ASOF_UTC=2026-11-09T17:24:43Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
INVENT_PASS=0
NO_DEBUG_OUTPUT_PASS_FROM_THIS_LANE=1

## Controlling tip

| Field | Value |
|-------|-------|
| Tip | `tip_cc79_integ_002` |
| SHA256 | `E950ADFB1E701BAB49BED0229627B9A5A1C5D719C5CD3EEECAE156678193E4A1` |
| Expect | `E950ADFB1E701BAB49BED0229627B9A5A1C5D719C5CD3EEECAE156678193E4A1` |
| SHA_MATCH | 1 |
| Session | `eo_sess_20261109-122217` |
| Run | `eo_run_20261109-122217` |
| Originating pane | COPILOT_CHAT input_id=1202 send_id=1204 transcript_id=1203 main=0x1FF06B8 |

## Scoreboard (fail-closed)

```
EXACTLY_ONCE=NOT_VERIFIED
DISPATCH_IDS=NONE
REQUESTS_PER_CLICK=MEASURED_DELTAS attempt=[0] input=[0] NOT_1_1
RESPONSES_PER_REQUEST=NOT_VERIFIED
PROMOTE=0
BLOCKERS=NO_CHAT_SEND_ATTEMPT,NO_INPUT_EVENT_BUTTON_CLICK,INPUT_ATTEMPT_NOT_1_1,FULL_CHAIN_1_1_UNPROVEN
NEXT_ACTION=Re-run with WaitIdle + Stop isolation if SUSPECTED dup; instrument pane-id on INPUT_EVENT if still UNBOUND; do not claim Debug/Output PASS from this lane
```

## Prior observation (reconciled - not this-run proof)

| Gate | Status |
|------|--------|
| Dispatch IDs 1 and 2 visible | CONFIRMED presence only (OUTPUT HWND sample: test / button-probe) |
| Exactly one request per click | NOT_VERIFIED (prior) |
| Exactly one response per request | NOT_VERIFIED (prior) |
| Ctrl+Enter | Not demonstrated in that transcript |
| Model button-probe how-to | Unsupported - not used as harness procedure |

Law: multiple AI response blocks after one visible submission NE proven duplicate send / callback / render cause.

## Measured chain (this run)

Path: `input event â†’ dispatch_id â†’ backend request â†’ response start/end â†’ transcript insertion`

| message | input_event | dispatch_id | request_id | response start (req/cb) | response end (ui) | transcript `[dispatch_id=N]` | outcome |
|---------|-------------|-------------|------------|-------------------------|-------------------|-------------------------------|---------|
| - | - | - | - | - | - | - | NO_DISPATCH |

### Per-click deltas (instrumented Send-button WM_COMMAND 1204)

| click | message | dINPUT_EVENT | dATTEMPT | dARMED | drequest_started | click_utc |
|------:|---------|-------------:|---------:|-------:|-----------------:|-----------|
| 1 | eo-corr-1 | 0 | 0 | 0 | 1 | 2026-11-09T17:22:53.9643805Z |

### Duplicate execution vs duplicate display

| Class | Result |
|-------|--------|
| Duplicate execution | NOT_PROVEN |
| Duplicate display | AI_BLOCKS_LE_REQUESTS (NE EXACTLY_ONCE) |
| PowerShell text in chat transcript | PS_IN_CHAT=0 |
| Ctrl+Enter this run | NOT_DEMONSTRATED_THIS_RUN |

## Counts

```
INPUT_EVENT_BUTTON_CLICK=0
CHAT_SEND_ATTEMPT=0
CHAT_SEND_ARMED=0
REQUEST_STARTED=1
CALLBACK_COMPLETE=1
UI_UPDATE_COMPLETE=1
AI_BLOCKS_VISIBLE=0
USER_BLOCKS_VISIBLE=0
TRANSCRIPT_TAG_IDS=
```

## Evidence paths

- Runtime journal: `F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\eo_corr\chat_runtime.log`
- Runtime copy: `F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts\chat_eo_corr_runtime_20261109-122217.log`
- Visible transcript: `F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\eo_corr\visible_transcript_eo_20261109-122217.txt`
- Receipt: `F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts\CHAT_EXACTLY_ONCE_CORRELATE_RECEIPT.txt`
- Runlog: `F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts\chat_eo_corr_run_20261109-122217.txt`
- Harness: `artifacts\chat_exactly_once_correlate.ps1`

## Visible transcript sample (truncated)

```

```

## Law

```
MULTI_RESPONSE_BLOCKS NE PROVEN_DUPLICATE_SEND
GENERATED_BUTTON_PROBE_HOWTO NE HARNESS
DISPATCH_ID_PRESENCE NE EXACTLY_ONCE
SOURCE_WIRED NE RUNTIME_REACHED NE TOKEN_SURVIVED NE PERFORMANCE_PASS
EXACTLY_ONCE=NOT_VERIFIED
PROMOTE=0
AUDIT_SEAL_UNCHANGED=1
```
