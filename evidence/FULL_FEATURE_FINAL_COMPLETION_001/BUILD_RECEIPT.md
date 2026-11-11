# BUILD_RECEIPT — tip_final_integ_002

ASOF_UTC=2026-11-09T10:13:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
TIP_NAME=tip_final_integ_002
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
SIZE=6152704
BUILD_DIR=F:\rawrxd\build_tip_debug_rel
CMAKE_BUILD_TYPE=RelWithDebInfo
CMAKE_FLAGS=-DRAWRXD_NATIVE_IDE_EXT=ON
TARGET=RawrXD-Win32IDE-Native-Ext
STAGE_ALSO=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_integ_002\
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
FROZEN_A4F_UNTOUCHED=1
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
```

## Source delta in this tip

- ExtHost wire trampoline + receipt write (`Win32IDE_ExtHostWire.cpp` / `js_extension_host.cpp`)
- `Win32IDE_lifecycle.cpp` AIM Ctrl: `GetKeyState || GetAsyncKeyState`
- ConPTY / chat send symbols retained; WaitForDebugEvent present

```
BUILD_SUCCESS != PRODUCT_PASS
PROMOTE=0
```
