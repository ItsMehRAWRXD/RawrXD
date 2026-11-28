# Build-integrity: fail closed when a product lacks the Deep2 engine — receipt (2026-11-28)

Implements WORKPACKAGES Package 6 (build integrity). Previously the IDE/CLI linked
`deep2_engine_lib` only inside `if(TARGET deep2_engine_lib)` guards and silently degraded
(CLI printed a STATUS; the IDE omitted it with NO message) when the engine was not
configured — so a green build could hide a missing required engine.

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: e8d9989e62
- File: `CMakeLists.txt` (+13)

## Change
- New option `RAWRXD_REQUIRE_PRODUCT_DEPS` (default ON; generalized from the initial
  deep2-only `RAWRXD_REQUIRE_DEEP2`).
- Product dependency guards now fail closed:
  - `deep2_engine_lib`: `RawrXD-Win32IDE-Native`, `RawrXD-Win32IDE-Native-Ext`, `RawrXD-CLI-V2` x2;
  - `rawrxd_production_hardening` (documented "hard dependency of the IDE"): `RawrXD-Win32IDE-Native`.
  - Pattern: `if(TARGET …)` link; `elseif(RAWRXD_REQUIRE_PRODUCT_DEPS)` → `FATAL_ERROR`;
    `else()` → STATUS/WARNING (deliberate dependency-less build, `RAWRXD_REQUIRE_PRODUCT_DEPS=OFF`).

## Verification (cmake 4.4.2 + Ninja, ~2 s configure)
| Configure | Result |
|-----------|--------|
| default (deep2 ON, REQUIRE ON) | `Configuring done`, exit 0 |
| `-DRAWRXD_BUILD_DEEP2_ENGINE=OFF` (REQUIRE ON) | `FATAL_ERROR: RawrXD-Win32IDE-Native requires deep2_engine_lib …`, exit 1 |
| `-DRAWRXD_BUILD_DEEP2_ENGINE=OFF -DRAWRXD_REQUIRE_DEEP2=OFF` | `Configuring done` + STATUS, exit 0 |

The silent-omission path is closed: a product can no longer configure green without the
required engine unless the engine-less build is explicitly requested.

## Coverage of the other Package 6 REQUIRED guards
- `rawrxd_gpu_compute` (vulkan_compute): **transitively covered** — `deep2_engine_lib`
  PUBLIC-links `rawrxd_gpu_compute` (CMakeLists.txt:3748-3749), and deep2 is now fail-closed
  (RAWRXD_REQUIRE_PRODUCT_DEPS). Source-missing is already `FATAL` at :3304
  (`ENABLE_VULKAN=ON but vulkan_compute.cpp missing`). The CLI's direct
  `if(TARGET rawrxd_gpu_compute)` is therefore redundant. `ENABLE_VULKAN=OFF` remains a valid
  dependency-less config.
- ggml submodule / rawr-reap / deep2_openai_server / computer_use: lower-priority or
  optional; not product-blocking on the default path.

## Build-level verification (beyond configure)
Forced a real recompile of a product dependency under the modified CMake:
```
cmake --build build\cmake-preset-ninja-release --target rawrxd_production_hardening
[1/3] Building CXX object .../ProductionRuntime.cpp.obj
[2/3] Linking CXX static library .../rawrxd_production_hardening.lib
=> BUILD_EXIT=0
```
Confirms the CMake changes do not break the actual compile/link of a real product dependency
(the D9025 /EHs-/EHa override warnings are pre-existing, unrelated to this change).

## State
IMPLEMENTED=1 COMPILED=1(configure) RUNTIME_REACHED=CONFIGURE_OK FUNCTIONALLY_VERIFIED=1
COMMITTED=1 PUSHED=0
NOT_APPLICABLE: full link/build of the monolith (heavy; configure-time gate is the deliverable).

## Next executable action
Push on request. Optionally extend the fail-closed rule to the -Ext IDE variant and any
other product that links deep2_engine_lib.