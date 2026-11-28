# Qt-free ABI verification — receipt (2026-11-28)

Milestone M-FIN-19 / NO_QT=1: verify the product binaries do not depend on Qt.

## Method
PE import analysis via `dumpbin /dependents` on the built executables:
- `build\cmake-preset-ninja-release\bin-msvc\rawr.exe` (RawrXD-CLI-V2)
- `build\cmake-preset-ninja-release\bin\RawrXD-Win32IDE-Native.exe` (GUI IDE)

## Result: PASS — no Qt imports
Imports are exclusively system / CRT / graphics / HTTP:
```
WS2_32.dll  WINHTTP.dll  dxgi.dll  dbghelp.dll  ADVAPI32.dll  USER32.dll
vulkan-1.dll  KERNEL32.dll  MSVCP140.dll  SETUPAPI.dll  VCRUNTIME140*.dll
api-ms-win-crt-*.dll (stdio/environment/runtime/string/convert/locale/filesystem/math/heap)
GDI32.dll
```
No `Qt5Core.dll` / `Qt6Core.dll` / `Qt5Gui.dll` / `Qt*Widgets.dll` or any Qt DLL is imported by either product.

## State
QT_FREE_ABI=PASS  NO_QT=1  NEW_EXTERNAL_PRODUCT_DEPENDENCIES=0
COMMITTED=1 PUSHED=0 (receipt). Build GREEN.