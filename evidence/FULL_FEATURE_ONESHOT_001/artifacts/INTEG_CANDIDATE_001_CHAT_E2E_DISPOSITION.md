# CHAT E2E uncanceled disposition — tip_integ_candidate_001

ASOF_UTC=2026-11-09T18:26:30Z
TIP_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
PROMOTE=0
MATURITY=82_UNCHANGED
INVENT_PASS=0

## Absorbed

```
P1=PASS
P2=PASS
INPUT_EVENT=PASS
OPEN_EDIT_SAVE=PASS
T05=PASS
INTEGRATED_P1_P2=PASS
E2E_CHAT_RESPONSE_CORRELATED=PASS
ISSUE49=4/11
CHAT_INPUT=PASS
```

## Best uncanceled attempts (same SHA, no rebuild)

| Stamp | ARMED | RESPONSE_START | Visible 1203 | Notes |
|-------|-------|----------------|--------------|-------|
| 20261109-124717 | PASS | FAIL | FAIL | WinHTTP stall after send; ctx=65536 |
| 20261109-125521 | PASS | FAIL | FAIL | ctx forced 8192 / maxTok 512; still no ReceiveResponse ok |
| 20261109-130358 | PASS | FAIL | FAIL | Journal-only poll (no UI SendMessage mid-flight); same stall |
| 20261109-131416 / 131922 | FAIL | FAIL | FAIL | Harness flake (input set / MAIN_HWND=0) — not product PASS |
| **20261109-132536** | **PASS** | **PASS** | **PASS** | Ollama restart cleared stuck sockets; ReceiveResponse ok; ui_complete=1; bytes=36; correlated ids |

Ollama direct `/api/generate` works; prior product-path stalls were stuck WinHTTP/Established sockets after hung IDE runs. Sealed PASS does **not** authorize PROMOTE or 11/11.

## Law

```
JOURNAL_AUTHORITATIVE=1
CANCELLED_BEFORE_UI_COMPLETE ≠ UNCANCELED_E2E_PASS
DASHBOARD ≠ PRODUCT_PASS
E6CF_RESTORE=HELD
PROMOTE=0
```
