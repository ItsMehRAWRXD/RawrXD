# CHAT_EXACTLY_ONCE_CORRELATE

ASOF_UTC=2026-11-09T15:06:32Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
INVENT_PASS=0
NO_DEBUG_OUTPUT_PASS_FROM_THIS_LANE=1

## Controlling tip

| Field | Value |
|-------|-------|
| Tip | tip_cc79_integ_002 |
| SHA256 | F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15 |
| SHA_MATCH | 1 |
| Session | eo_sess_20261109-100556 |
| Run | eo_run_20261109-100556 |
| Chat session (product) | session=1 (from CHAT_SEND_ARMED) |
| Originating pane | COPILOT_CHAT input_id=1202 send_id=1204 output_id=1203 main=0x3520BDA |

## Scoreboard (fail-closed)

```
EXACTLY_ONCE=NOT_VERIFIED
DISPATCH_IDS=1,2
REQUESTS_PER_CLICK=1,1
RESPONSES_PER_REQUEST=1
PROMOTE=0
BLOCKERS=TRANSCRIPT_VISIBLE_TAG_MISSING,FULL_CHAIN_1_1_UNPROVEN,TIP_LACKS_TRANSCRIPT_INSERT_JOURNAL
NEXT_ACTION=Capture real IDC_COPILOT_CHAT_OUTPUT (1203) text preferring Welcome/AI/[dispatch_id]; do not claim Debug/Output PASS from this lane
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

Path: input event -> dispatch_id -> backend request -> response start/end -> transcript insertion

Harness: `artifacts\chat_exactly_once_correlate.ps1` (Send-button WM_COMMAND 1204 only; messages eo-corr-1 / eo-corr-2). Model how-to was not used.

| message | input_event | dispatch_id | request_id | response start | response end | transcript [dispatch_id=N] | outcome |
|---------|-------------|-------------|------------|----------------|--------------|----------------------------|---------|
| eo-corr-1 | BUTTON_CLICK | 1 | 1 | request_started=1; callback partial stream then complete=1 | ui_update complete=1 rendered=1 | MISSING (visible HWND sample was debug/log text, not chat) | ARMED |
| eo-corr-2 | BUTTON_CLICK | 2 | 2 | request_started=1; callback partial stream then complete=1 | ui_update complete=1 rendered=1 | MISSING (same) | ARMED |

### Per-click deltas (instrumented)

| click | message | dINPUT_EVENT | dATTEMPT | dARMED | drequest_started | click_utc |
|------:|---------|-------------:|---------:|-------:|-----------------:|-----------|
| 1 | eo-corr-1 | 1 | 1 | 1 | 1 | 2026-11-09T15:06:20.5671533Z |
| 2 | eo-corr-2 | 1 | 1 | 1 | 1 | 2026-11-09T15:06:25.8965227Z |

### Journal excerpt (authoritative for execution)

```
SESSION_OPEN session_id=eo_sess_20261109-100556 run_id=eo_run_20261109-100556
INPUT_EVENT kind=BUTTON_CLICK path=WM_COMMAND_BN_CLICKED
CHAT_SEND_ATTEMPT dispatch_id=1 ...
request_started request_id=1 model=bigdaddyg-productivity-local:latest
CHAT_SEND_ARMED dispatch_id=1 request_id=1 session=1
... streaming callback/ui_update complete=0 ...
callback request_id=1 complete=1
ui_update request_id=1 rendered=1 complete=1
INPUT_EVENT kind=BUTTON_CLICK path=WM_COMMAND_BN_CLICKED
CHAT_SEND_ATTEMPT dispatch_id=2 ...
request_started request_id=2 ...
CHAT_SEND_ARMED dispatch_id=2 request_id=2 session=1
... streaming ...
callback request_id=2 complete=1
ui_update request_id=2 rendered=1 complete=1
```

### Duplicate execution vs duplicate display

| Class | Result |
|-------|--------|
| Duplicate execution | NOT_PROVEN - no extra ATTEMPT vs INPUT (2=2); no BUSY/SUPERSEDE |
| Duplicate display | NOT_PROVEN - one ui_update complete=1 per request_id; many partial stream chunks are not extra responses |
| PowerShell text in chat | PS_IN_CHAT=0 (not observed in this-run samples) |
| Ctrl+Enter this run | NOT_DEMONSTRATED_THIS_RUN |

Notes:
- Streaming produces many `callback`/`ui_update` with `complete=0` per request; exactly one `complete=1` per request_id was measured.
- Visible HWND scrape returned IDE/debug log lines (`[CHAT_RUNTIME] ui_update...`), not chat `> User:` / `[dispatch_id=N]` text. That is a capture miss, not a proven duplicate-display finding.
- Tip binary lacks `TRANSCRIPT_INSERT` string (source has it; tip SHA F5F4807E does not). User-line insert evidence therefore stays journal/UI incomplete on this tip.

## Counts

```
INPUT_EVENT_BUTTON_CLICK=2
CHAT_SEND_ATTEMPT=2
CHAT_SEND_ARMED=2
REQUEST_STARTED=2
CALLBACK_COMPLETE=2
UI_UPDATE_COMPLETE=2
TRANSCRIPT_TAG_IDS=
POWERSHELL_IN_CHAT=0
```

## Evidence paths

- Runtime journal: `candidates\tip_cc79_integ_002_eo_corr\chat_runtime.log`
- Runtime copy: `artifacts\chat_eo_corr_runtime_20261109-100556.log`
- Visible scrape (mis-attributed debug text): `candidates\tip_cc79_integ_002_eo_corr\visible_transcript_eo_20261109-100556.txt`
- Receipt: `artifacts\CHAT_EXACTLY_ONCE_CORRELATE_RECEIPT.txt`
- Runlog: `artifacts\chat_eo_corr_run_20261109-100556.txt`
- Harness: `artifacts\chat_exactly_once_correlate.ps1`

## Law

```
MULTI_RESPONSE_BLOCKS NE PROVEN_DUPLICATE_SEND
GENERATED_BUTTON_PROBE_HOWTO NE HARNESS
DISPATCH_ID_PRESENCE NE EXACTLY_ONCE
JOURNAL_1_1_DELTAS NE EXACTLY_ONCE
SOURCE_WIRED NE RUNTIME_REACHED NE TOKEN_SURVIVED NE PERFORMANCE_PASS
EXACTLY_ONCE=NOT_VERIFIED
PROMOTE=0
AUDIT_SEAL_UNCHANGED=1
ENGINEERING_MATURITY=82%_UNCHANGED
```
