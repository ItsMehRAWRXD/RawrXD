# Configuration Completion Evidence Ledger — 2026-11-28

Goal: CONFIG_MILESTONES=8/8, CONFIG_CERTIFIED=1.
Posture until then: CERTIFIED=0 RELEASE=HELD PROMOTE=0 PUSHED=0.
Baseline HEAD at start: 2f8f323306.

## Unit U1 — M-CFG-01 / M-CFG-02 / M-CFG-03 / M-CFG-07 core

Commit: 9d0d5f2061
Files:
- CMakePresets.json (product, product-tests, install, product-msvc, product-msvc-tests, package, CTest presets)
- cmake/Install.cmake (install rules for products, shaders, config template, registry, VERSION)
- CMakeLists.txt (include Install.cmake; rawrxd_config library + config_core_test)
- include/rawrxd/config/AppPaths.h, src/config/AppPaths.cpp
- include/rawrxd/config/ConfigStore.h, src/config/ConfigStore.cpp
- include/rawrxd/config/ModelDiscovery.h, src/config/ModelDiscovery.cpp
- tests/config/config_core_test.cpp
- src/win32app/main_win32.cpp (all F:\ hardcoded paths replaced)
- rawrxd.config.json (version 2, portable paths, vulkanCompute=true, real default model)

Build receipt:
- `cmake --preset product-msvc-tests` -> configure OK, MSVC 19.44.35228, Vulkan 1.4.357.0, hardening ON, LTO ON, 89 tests registered.
- `cmake --build build/cmake-preset-ninja-release --target config_core_test` -> exit 0.
- `config_core_test.exe` -> `config_core_test: PASS`, exit 0.
- `cmake --build ... --target RawrXD-Win32IDE-Native` -> linked `bin\RawrXD-Win32IDE-Native.exe`.

Acceptance evidence:
- Path override, v1->v2 migration, drive-letter rejection, atomic write, GGUF metadata discovery all asserted in config_core_test.

Remaining for U1:
- Full `product-msvc-tests` build (1609 steps) must complete; previous run stopped only on the now-fixed main_win32.cpp error.
- Install-tree run from a clean directory outside F:\rawrxd.

## Unit U2 — M-CFG-04 / M-CFG-08 (in progress)

Script: scripts/gen_model_registry.ps1
Status: running (SHA-256 over all on-disk GGUFs).
Outputs: models/registry.json (v15), models/acquisition.json.

## Blockers
- `deep2_multitoken_decode_parity` remains failed (M-FIN-01, outside config scope but blocks CTEST=ALL PASS).
- Two skipped tests (#7, #73) not yet investigated.
- Full product build not yet re-run to completion after U1.