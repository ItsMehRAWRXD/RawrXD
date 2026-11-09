# EXTENSIONHOST_INTEGRATION_REPAIR_001 — patch plan

Status: source-only preparation; no source files modified, no build/execution performed.

## Ordered changes

1. Route ownership: make the production LocalServer and HeadlessIDE extension branches call `ProductExtensionRuntime::HandleRoute`; retain `ProductGuiRoutes` only for unrelated thin adapters. Relevant current call sites: `src/win32app/Win32IDE_LocalServer.cpp:1117-1129`, `src/win32app/HeadlessIDE_GuiRoutes.cpp:58-65`. Add a route-ownership guard so a future thin fallback cannot intercept extension paths silently.
2. Target linkage: add the ProductExtensionRuntime sources and `ExtensionHostWorker_main.cpp` to the intended CMake graph. Current source list is in `src/win32app/`; target authority is the `RawrXD-Win32IDE` target around `CMakeLists.txt:7530`. The existing `cmake/SmokeE2EIPC.cmake:25-40` defines an ExtensionHost target but is not by itself proof that the production IDE target depends on it.
3. Deployment: add an explicit `add_dependencies(RawrXD-Win32IDE RawrXD-ExtensionHost)` and a post-build copy of `$<TARGET_FILE:RawrXD-ExtensionHost>` to the IDE runtime directory, guarded by the same target/configuration.
4. Launch correctness: centralize Windows argument quoting; validate the resolved executable with a canonical path under the candidate runtime directory; capture `GetLastError()` immediately after `CreateProcessA` fails.
5. Readiness: introduce a per-launch, collision-resistant IPC identity and a bounded parent/child handshake. The child must signal readiness only after protocol initialization; the parent must not return `active=true` before that signal.
6. Shutdown: signal the child stop endpoint, wait a bounded interval, then terminate only if the child does not exit; clear handles/PID/state in all paths.

## Minimal file set

- `src/win32app/Win32IDE_LocalServer.cpp`
- `src/win32app/HeadlessIDE_GuiRoutes.cpp`
- `src/win32app/ProductGuiRouteAdapters.hpp`
- `src/win32app/ProductExtensionRuntime_Host.cpp`
- `src/win32app/ProductExtensionRuntime_Activate.cpp`
- `src/win32app/ExtensionHostWorker_main.cpp`
- `src/win32app/ProductExtensionRuntime_Internal.hpp` or a new small launch/IPC header
- root `CMakeLists.txt` and/or `cmake/SmokeE2EIPC.cmake`
- focused extension runtime tests under `tests/`

## Constraints

Candidate branch/worktree only. Preserve frozen SHA prefix `748B210A`; keep `PROMOTE=0`, `TIP_CLIMB=HOLD`, `CERTIFIED=0`, `PRODUCT_RUNTIME=NOT_REVALIDATED`.

