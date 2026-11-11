# Tip stage plan — tip_ext_host_001

ASOF_UTC=2026-11-09T08:00:00Z
PROMOTE=0
TIP_CLIMB=HOLD

```
BASE_FROM=current tip sources (Win32IDE.cpp lineage incl. drainCancelledInferenceWorker)
IMMUTABLE_A4F=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
STAGE_OUT=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe
NEVER_COPY_OVER_A4F=1
```

## Ordered steps (next turns)

1. **Restore / land missing TUs** into a dedicated full-feature lane (do not mutate slim acceptance):
   - Mirror `js_extension_host.{hpp,cpp}` (+ polyfill) from `~dev\rawrxd\src\core\` into buildable path **or** add include/source path to that mirror without altering A4F package.
   - Recover `quickjs_extension_host.cpp`, `quickjs_vscode_bindings.cpp`, `vscode_extension_api.*`, `ExtensionLoader.hpp` from authority backup / historical tree (currently FILE_MISSING).
2. **CMake**: add opt-in target or `RAWRXD_NATIVE_IDE_EXT=ON` source append for tip_ext only — keep default slim `RawrXD-Win32IDE-Native` identical to A4F lineage when EXT off.
3. **Product wire**: from Win32IDE tip path, call `JSExtensionHost::instance().initialize()` then `loadVSIX(path, installDir)` (or loadExtensionFromDir) behind an explicit full-feature gate; wire sidebar Install to that path.
4. **Build** into a separate out dir; copy EXE only to `package\tip_ext_host_001\`; hash SHA-256.
5. **Smoke**: same-SHA launch → EXT load of a fixture VSIX/dir under evidence → record `EXT_LOAD=PASS|FAIL` from real exercise only.
6. **Do not** transfer POST_E59D / 3B72; do not set PROMOTE.

## This turn

```
PLAN_WRITTEN=1
SOURCE_WIRED=0
TIP_BUILT=0
EXT_LOAD=NOT_RUN
```
