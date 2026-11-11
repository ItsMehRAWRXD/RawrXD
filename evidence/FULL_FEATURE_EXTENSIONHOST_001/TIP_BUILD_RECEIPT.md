# tip_ext_host_001 — TIP_BUILD_RECEIPT

ASOF_UTC=2026-11-09T08:30:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
TARGET=RawrXD-Win32IDE-Native-Ext
CMAKE_OPTION=RAWRXD_NATIVE_IDE_EXT=ON
BUILD_DIR=F:\rawrxd\build_tip_ext_host_001
STAGE_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe
TIP_SHA256=272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8
TIP_SIZE=2220544
QUICKJS=F:\rawrxd\3rdparty\quickjs_ng
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
FROZEN_A4F_UNTOUCHED=1
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
EXT_LOAD=NOT_RUN
ATTEMPTED_LOAD_SMOKE=0
BUILD_ALONE_NE_EXT_PASS=1
```

## Restored TUs (from g:\~dev\rawrxd)

- `src/modules/quickjs_extension_host.cpp`
- `src/modules/quickjs_vscode_bindings.cpp`
- `src/modules/vscode_extension_api.cpp` + `.h`
- `src/modules/ExtensionLoader.hpp`
- `src/core/js_extension_host.{cpp,hpp}`
- `src/core/extension_polyfill_engine.cpp`
- `src/core/plugin_signature.cpp` + `include/plugin_signature.h`
- `include/quickjs_extension_host.h`
- `src/core/model_memory_hotpatch.hpp` + `patch_result.hpp`
- QuickJS-ng runtime sources under `3rdparty/quickjs_ng/`

## CMake

Separate opt-in target `RawrXD-Win32IDE-Native-Ext` (slim `RawrXD-Win32IDE-Native` unchanged when EXT=OFF).

## Logs

- `TIP_EXT_CMAKE_CONFIG.log`
- `TIP_EXT_BUILD.log`

## Law

```
BUILD_ALONE ≠ EXT_PASS
NOT_RUN ≠ PASS
PROMOTE=0
```
