# DISPATCH_ID_CORRELATION

ASOF_UTC=2026-11-09T13:16:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0

## Scope

Per-message `dispatch_id` correlation on sealed HWND tip `30B9BA78…`
(`tip_hwnd_repair_001` / `tip_final_007`, SHA
`30B9BA7899FB8C7D4A0AAE3B1B81883B5C7DBA2606CFA28396A3517273BFC393`).

This is **not** exactly-once certification.

## Preserved seals

| Item | Status |
|------|--------|
| tip006 `5A71CA26…` (OUTPUT=FAIL) | PRESERVED — not overwritten |
| external drift `69FE3D92…` | NOT the tip006 seal |
| A4F / CC79 / `CHAT_TRANSCRIPT_17_RECONCILE.md` | UNTOUCHED |

## Result

```
DISPATCH_ID_CORRELATION=RUNTIME_AND_TRANSCRIPT_HIT
DISPATCH_ID_WIRE=SOURCE_STRINGS_PRESENT
DISPATCH_ID_RUNTIME_HITS=6
DISPATCH_ID_TRANSCRIPT_THIS_RUN_HITS=1
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
BACKEND_RESPONSE=NOT_VERIFIED
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
```

## Message → dispatch_id → outcome

| message | dispatch_id | send_seq | outcome | request_id | transcript `[dispatch_id=N]` |
|---------|-------------|----------|---------|------------|--------------------------------|
| `corr-probe-1` | 1 | 1 | ARMED | 1 | THIS_RUN_PRESENT (`> User: [dispatch_id=1] corr-probe-1`) |
| `corr-probe-2` | 2 | 2 | BUSY | — | N/A_BUSY_NOT_APPENDED |
| `corr-probe-3` | 3 | 3 | BUSY | — | N/A_BUSY_NOT_APPENDED |

Runtime journal (this run):

```
CHAT_SEND_ATTEMPT dispatch_id=1 send_seq=1 bytes=12
CHAT_SEND_ARMED dispatch_id=1 send_seq=1 request_id=1 session=8
CHAT_SEND_ATTEMPT dispatch_id=2 send_seq=2 bytes=12
CHAT_SEND_BUSY dispatch_id=2 send_seq=2 dispatched=0
CHAT_SEND_ATTEMPT dispatch_id=3 send_seq=3 bytes=12
CHAT_SEND_BUSY dispatch_id=3 send_seq=3 dispatched=0
```

## Evidence paths

- Runtime: `candidates\tip_dispatch_corr_001\chat_runtime.log`
- Runtime copy: `artifacts\dispatch_id_corr_chat_runtime_20261109-081525.log`
- Visible transcript: `candidates\tip_dispatch_corr_001\visible_transcript_sample.txt`
- Receipt: `artifacts\DISPATCH_ID_CORRELATION_RECEIPT.txt`
- Runlog: `artifacts\dispatch_id_corr_run_20261109-081525.txt`
- Harness: `harness\dispatch_id_correlation_measure.ps1`

## Fail-closed notes

- Correlation = ATTEMPT→ARMED/BUSY/REJECTED journal match + ARMED-path transcript tag for this-run text.
- Historical transcript tags from prior probes exist in the control; only
  `[dispatch_id=1] corr-probe-1` is counted as this-run transcript evidence.
- `EXACTLY_ONCE_DELIVERY=NOT_VERIFIED` (correlation ≠ exactly-once cert).
- `BACKEND_RESPONSE` / `CHAT_FULL_ACCEPTANCE` remain `NOT_VERIFIED`.
