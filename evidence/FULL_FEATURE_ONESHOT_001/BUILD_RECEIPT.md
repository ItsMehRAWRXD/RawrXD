# BUILD_RECEIPT — FULL_FEATURE_ONESHOT_001

ASOF_UTC=2026-11-09T10:01:30Z
SOURCE_REVISION=b7db735b7644d4c9df57cef75a6e4c28c590dccf
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

## Build

```
ninja -C F:\rawrxd\build_tip_ext_host_001 RawrXD-Win32IDE-Native-Ext
```

## Outputs

| Artifact | SHA-256 | Size |
|----------|---------|------|
| tip_ext_host_006 / tip_final_002 | `633AB013E37612C55F26615CE3B07633B1401536B00F5C4E2D75076451232363` | 2749952+ |
| Frozen A4F | `A4F083DF…` | 2601472 UNTOUCHED |

## Source landed this continue

- `Win32TerminalManager.cpp` — ConPTY OS26300 capture PASS
- `js_extension_host.cpp` — `invokeRegisteredCommand`; local-first executeCommand
- `Win32IDE_ExtHostWire.cpp` — headless-safe `--ext-cmd` via trampoline
- fixture `ext_hello/extension.js` — no MessageBox in ping

```
FROZEN_A4F_UNTOUCHED=1
BUILD_ALONE_NE_PRODUCT_PASS=1
```
