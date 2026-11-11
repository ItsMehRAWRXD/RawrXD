# tip_final_integ_002

```
TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
BUILD=RelWithDebInfo build_tip_debug_rel
TARGET=RawrXD-Win32IDE-Native-Ext
SIZE=6152704
FROZEN_A4F_UNTOUCHED=1
PROMOTE=0
PRODUCT_PASS=0
```

## Measured on this SHA

| Gate | Result |
|------|--------|
| EXT_LOAD / lifecycle | PASS (INIT/LOAD/ACTIVATE/CMD; malformed FAULT_ISOLATED) |
| Chat AIM 7/7 | PASS (CJK PASS) |
| Terminal `--term-smoke` | PASS (CONPTY + ALIVE_ECHO) |
| WaitForDebugEvent (image) | HIT |
| Debug backend headless | PASS (SESSION_REAL=1 via build_tip_debug_rel tools) |
| IDE debug UI / four-panel | NOT_RUN / BLOCKED |

## Receipts

- `..\..\logs\ext_smoke_tip_final_integ_002.txt`
- `..\..\artifacts\CHAT_CTRL_ENTER_RECEIPT.txt`
- `..\..\artifacts\term_smoke_receipt_CC79.txt`
- `..\..\artifacts\DEBUG_BACKEND_VERIFY_RECEIPT.txt`
- `..\..\artifacts\four_panel_hwnd_probe_CC79.txt`

Never overwrote frozen A4F package exe.
