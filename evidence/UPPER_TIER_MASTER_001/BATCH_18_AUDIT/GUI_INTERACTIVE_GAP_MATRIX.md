# Batch 18 — Interactive GUI Gap Matrix (P06–P11)

```
ASOF_UTC=2026-11-11T19:15:00Z
MODE=RUNTIME_PARTIAL
AUTHORITY=F:\rawrxd
CROSS_CHECK=G:\~dev\rawrxd (as needed)
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
SOURCE_WIRED ≠ RUNTIME_REACHED
NOT_RUN ≠ PASS
ESTIMATES_UNCHANGED=82/58/69/63
RUNTIME_ACCEPTANCE=PARTIAL_2_OF_6
TIP_SHA=D1B17F66C5BD951BADD51FEE31326EAAE758B1E3F605E761AB4D82D255A32ABF
HARNESS_PS_SMOKE=RUNTIME_EXERCISED_UNPROMOTED
```

## Controlling blockers

| ID | Status | Blocker |
|----|--------|---------|
| G1_NATIVE_EXE_ABSENT | CLEARED | Tip at `build_win32ide\bin\Release` (checklist `Release\` path stale/ABSENT) |
| TIP_SHA_BOUND | CLEARED | Live tip `D1B17F66…` (user brief `16D85B1C…` superseded 19:06:28Z) |
| P07_HWND_VISIBILITY | FAIL | Tab count/sel reached; pane HWND visibility unproved; notify follow-up exited |
| P08_RESIZE_SESSION | FAIL | Splitter `IDC_SPLITTER=1016` drag + session `panel.height` reload unproved |
| P09_ITEMS_ZERO | FAIL | Problems list `1312`; items=0; click-to-line not exercised |
| P11_STALE_FENCE | FAIL | Chat Send/Stop present; Request A/B + stale fence not verified |

## Summary

| Metric | Value |
|--------|-------|
| Gates | 6 (P06–P11) |
| source_wired | **6/6** |
| runtime_reached | **6/6** |
| product_runtime_pass | **2/6** (P06, P10) |
| Disposition | RUNTIME_EXERCISED_PARTIAL · CERTIFIED=0 · PROMOTE=0 |

## Gate matrix

| Gate | Requirement | source_wired | runtime_reached | product_pass | Exact blockers | Key evidence |
|------|-------------|:------------:|:---------------:|:------------:|----------------|--------------|
| **P06** | PowerShell Execute/Clear/Stop (5610/5611/5612) | 1 | 1 | 1 | — | `RUNTIME_EVIDENCE/gui_gates_run_20261111-141057.txt`; B17 `ps_smoke_run_20261111-140629.txt` |
| **P07** | Bottom-dock 4-tab switching | 1 | 1 | 0 | Pane HWND vis unproved; notify follow-up exited | `RUNTIME_EVIDENCE/GUI_FOLLOWUP_RECEIPT.txt` |
| **P08** | Dock resize / restore | 1 | 1 | 0 | Height change + session reload unproved | `RUNTIME_EVIDENCE/GUI_GATES_RECEIPT.txt` |
| **P09** | Problems click-to-line | 1 | 1 | 0 | ITEMS=0; caret NOT_RUN | `RUNTIME_EVIDENCE/GUI_FOLLOWUP_RECEIPT.txt` |
| **P10** | Native IDE startup exceptions | 1 | 1 | 1 | — | Cold×3 MAIN_HWND + bind in `gui_gates_run_20261111-141057.txt` |
| **P11** | Cancellation / recovery | 1 | 1 | 0 | A/B + stale fence NOT_VERIFIED | `RUNTIME_EVIDENCE/GUI_FOLLOWUP_RECEIPT.txt` |

## P06 note (mandatory)

PowerShell **5610/5611/5612** frame routing is **SOURCE_APPLIED** and now **RUNTIME_PASS** on tip `D1B17F66…` (Execute output + Clear shrink + Stop posted + IDs bound). Harness still seals `PRODUCT_PASS=0` / unpromoted; checklist ledger marks P06=PASS from live evidence. `CERTIFIED=0` `PROMOTE=0`.

## Law reminders

- Prior candidate PASS (T080, FOUR_PANEL_1_17, ONESHOT PS) ≠ Batch-18 tip acceptance.
- Crash / stall / NOT_RUN ≠ PASS.
- This runtime lane did **not** edit product sources.
- Estimates must **not** be raised from this inventory.

## Next executable gates

1. P07 — real `switchPanelTab` HWND visibility for all 4 panes (no probe crash).
2. P08 — splitter-1016 drag height change + session `panel.height` reload.
3. P09 — populate Problems ≥1 item then 1399 caret on tip.
4. P11 — Request A → Stop → Request B with response/stale-fence proof.

## Companion

Machine-readable: `GUI_INTERACTIVE_GAP_MATRIX.json`
Disposition: `DISPOSITION_RUNTIME_GATE.txt`

