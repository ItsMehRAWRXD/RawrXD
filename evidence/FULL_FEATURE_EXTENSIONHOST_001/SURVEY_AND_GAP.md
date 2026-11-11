# Survey — ExtensionHost evidence + loadVSIX wiring

ASOF_UTC=2026-11-09T08:00:00Z
PROMOTE=0

## 1. Evidence under F:\rawrxd\evidence

Literal `EXTENSIONHOST_*` seal directories: **NONE found**.

Closest EXT-related seals:

| Path | EXT disposition |
|------|-----------------|
| `DAILY_DRIVER_CLOSE_001\SMOKE_T16_EXT.md` | `EXT_LOAD=NOT_RUN` — tip slim EXE has no linked ExtensionHost/loadVSIX/QuickJS |
| `DAILY_DRIVER_CLOSE_001\SLIM_DAILY_DRIVER_EXT_POLICY.md` | EXT **OUT_OF_SCOPE** for slim profile; full-feature requires separate candidate |
| `DAILY_DRIVER_CLOSE_001\FULL_FEATURE_NEXT_TRACK.md` | Track step 1 = Native ExtensionHost / VSIX integrate |
| `POST_E59D_CANDIDATE_001\COMPILE_EXT_SMOKE_71D14597.md` | `EXTENSION_SMOKE=NOT_RUN` (compile/run PASS only) |

## 2. Tip lineage (current)

```
CONTROLLING_SLIM_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
TIP_LINEAGE_NOTE=drainCancelledInferenceWorker present on Win32IDE.cpp tip sources
CMAKE_TARGET=RawrXD-Win32IDE-Native
CMAKE_SURFACE=F:\rawrxd\CMakeLists.txt RAWRXD_NATIVE_IDE_SOURCES
```

`RAWRXD_NATIVE_IDE_SOURCES` includes Win32IDE.cpp / Sidebar / GhostText / Deep2 bridges etc.
It does **not** include:

- `Win32IDE_Core.cpp` (only call sites for `initVSCodeExtensionAPI` / `detachJSExtensionHosts` / `ExtensionLoader`)
- any `js_extension_host*.cpp`
- any `quickjs_extension_host*.cpp`
- any `extension_polyfill_engine.cpp`
- any `vscode_extension_api*.cpp`

## 3. Source inventory (loadVSIX / ExtensionHost)

### Present (mirror / non-slim tree)

| Artifact | Path |
|----------|------|
| `JSExtensionHost` API + `loadVSIX` decl | `F:\rawrxd\~dev\rawrxd\src\core\js_extension_host.hpp` |
| Full host impl (`loadVSIX` @ ~L2078) | `F:\rawrxd\~dev\rawrxd\src\core\js_extension_host.cpp` |
| Headless fail-closed stubs | `F:\rawrxd\~dev\rawrxd\src\core\js_extension_host_headless_impl.cpp` |
| Production companion | `F:\rawrxd\~dev\rawrxd\src\core\js_extension_host_production.cpp` |
| Polyfill engine TU | `F:\rawrxd\~dev\rawrxd\src\core\extension_polyfill_engine.cpp` |

### Absent from F:\rawrxd tree (link blockers)

| Missing surface | Referenced by | Status |
|-----------------|---------------|--------|
| `src/modules/quickjs_extension_host.cpp` | `~dev/rawrxd/CMakeLists.txt` Phase 36 | **FILE_MISSING** (0 hits under F:\rawrxd) |
| `src/modules/quickjs_vscode_bindings.cpp` | same | **FILE_MISSING** |
| `src/modules/vscode_extension_api.cpp` / headers | polyfill + host deps | **FILE_MISSING** |
| `src/modules/ExtensionLoader.hpp` | `#include` from `Win32IDE_Core.cpp` | **FILE_MISSING** |
| `JSExtensionHost` under `F:\rawrxd\src\core\` | production tip tree | **NOT_MIRRORED** (only under `~dev\rawrxd\`) |
| QuickJS runtime lib / headers | host initialize path | **NOT_ON_SLIM_LINK** |

### Tip EXE product path (slim)

| Symbol / surface | On tip EXE? |
|------------------|-------------|
| `JSExtensionHost::instance` | NO |
| `JSExtensionHost::initialize` | NO |
| `JSExtensionHost::loadVSIX` | NO |
| `JSExtensionHost::activateExtension` | NO |
| `QuickJSExtensionHost::*` | NO |
| `initVSCodeExtensionAPI` | Call site only in Core (Core **not linked** into Native tip); definition not found in tip TUs |
| `detachJSExtensionHosts` | same |
| `RawrXD::ExtensionLoader` | Core-only; header missing |
| Sidebar `m_hwndExtensionsList` / `loadInstalledExtensions` | YES — **discovery list only** |
| `installExtension` / `enableExtension` | UI stubs / in-memory flags — **≠ VSIX load** |
| `drainCancelledInferenceWorker` | YES — tip lineage GhostText cancel path |

## 4. Repo extensions corpus (not wired)

`F:\rawrxd\extensions\*` exists (e.g. `rawrxd-lsp-client`, `rawrxd_extension_runtime`). Per T16 EXT seal: present corpus ≠ linked into tip EXE.

## 5. Gap seal (exact)

```
GAP_ID=EXT_HOST_TIP_LINK_SURFACE
BLOCKERS=
  1. RAWRXD_NATIVE_IDE_SOURCES excludes ExtensionHost TUs and Win32IDE_Core.cpp
  2. js_extension_host*.cpp not present under F:\rawrxd\src\ (only ~dev mirror)
  3. quickjs_extension_host.cpp / quickjs_vscode_bindings.cpp FILE_MISSING
  4. vscode_extension_api.* FILE_MISSING
  5. ExtensionLoader.hpp FILE_MISSING
  6. No tip CLI/menu/API invoking loadVSIX on Native EXE
  7. QuickJS runtime not linked on slim target
FEASIBLE_ONE_TURN_WIRE=0
TIP_EXE_BUILT=0
EXT_LOAD=NOT_RUN
```
