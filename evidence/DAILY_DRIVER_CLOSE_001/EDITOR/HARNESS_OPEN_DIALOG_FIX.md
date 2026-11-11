# File→Open harness fix (not a product PASS)

ASOF_UTC=2026-11-09T07:15:00Z
FROZEN_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0

## Separation

| Path | Result | Locus |
|------|--------|-------|
| CLI open (`exe path`) | PASS | product open/load OK |
| Menu → common dialog | PASS (after harness fix) | was harness BM_CLICK deadlock |
| T07 unicode + binary reject | PASS | menu+CLI reject |
| T08 ten-tab | FAIL MAIN_LOST | product process/HWND exit mid multi-open |
| T10 hard-kill | PASS | marker readback+checkpoint |

## Root cause (harness — closed)

`DriveFileDialog` used cross-thread `SendMessage(BM_CLICK)` → ~80s OPEN_RESULT hang.
Fixed: `PostMessage(WM_COMMAND, IDOK)` + Enter; full path normalize; T10 refuse kill without marker.

## Additional harness (this turn)

- `SummarizeTabControls` (was missing → ENUM_UNAVAILABLE)
- Rebind `FindMain` each T08 open
- `Invoke-OpenAddTab` requires title leaf proof

## Not claimed

```
DAILY_DRIVER_ACCEPTANCE=FAIL (T08 open)
PRODUCT_PASS=0
PROMOTE=0
TIP_71D14597 ≠ this SHA score
```
