# EXTENSIONHOST_CHILD_LAUNCH_ROOT_001 — source-only diagnosis

As-of: 2026-11-02  
Authority: source inspection only. No build, execution, frozen-tip modification, or promotion was performed.

## Result

The historical `73368D76…` failure boundary is established as **pre-launch routing/linkage**, not a proven `CreateProcessA` failure:

1. The failing candidate routed `/api/extensions/*` through `ProductGuiRoutes::extensionsJson`, which deliberately returned `adapter=product_thin`, empty inventory, and `host_pid:0` (`src/win32app/ProductGuiRouteAdapters.hpp:51-62`).
2. Because that route returned before `ProductExtensionRuntime::HandleRoute`, `Activate()` and `SpawnHostUnlocked()` were never reached for the failing path.
3. The runtime implementation did exist, but the repair receipt records that its translation units were not linked into candidate `73368`, and `RawrXD-ExtensionHost.exe` was absent beside that candidate (`evidence/EXTENSION_RUNTIME_73368_REPAIR_001/DIAGNOSIS.md`, root-cause items 1–3).
4. The candidate-only repair then wired the runtime routes, linked the runtime TUs, and supplied the worker executable; `MATRIX_002` recorded PASS=6/6 on candidate `FD07CA61…`. This validates the repair candidate only, not the frozen tip.

## Launch path

`IDE command/API request → Win32IDE_LocalServer or HeadlessIDE route → ProductExtensionRuntime::HandleRoute → Activate → SpawnHostUnlocked → CreateProcessA → ExtensionHostWorker_main::WinMain`.

The exact source call graph and line ranges are in `CALLGRAPH.md`.

## Boundary classification

| Boundary | Finding | Status |
|---|---|---|
| Route dispatch | Thin adapter could terminate the request before real runtime | **Confirmed historical root cause** |
| Runtime linkage | ProductExtensionRuntime objects were absent from failing candidate | **Confirmed by repair receipt** |
| Worker deployment | Worker EXE absent beside failing candidate | **Confirmed by repair receipt** |
| Executable resolution | `ExeDir()/RawrXD-ExtensionHost.exe` is resolved and existence-checked | Source path established; failing-candidate runtime invocation not independently reproduced |
| Command-line quoting | `rec.id` is unquoted; `rec.path` is only wrapped, with no escaping | **Confirmed source defect risk**; impact not runtime-proven |
| Working directory | `ExeDir()` is passed as `lpCurrentDirectory` | Source behavior established; no evidence this caused the historical failure |
| Environment inheritance | `lpEnvironment=nullptr`, so inherited environment is used | Source behavior established; no evidence this caused the historical failure |
| Process creation | `CreateProcessA` failure returns false without `GetLastError()` receipt | **Missing diagnostic evidence** |
| IPC/readiness | Worker creates a named stop event and blocks; no parent/child handshake or readiness signal exists | **Confirmed source gap** |
| Shutdown | Parent terminates process and closes handle; worker waits on stop event that is never signaled by this path | **Confirmed source lifecycle gap** |

## Control state

`PROMOTE=0`  
`TIP_CLIMB=HOLD`  
`CERTIFIED=0`  
`PRODUCT_RUNTIME=NOT_REVALIDATED`

