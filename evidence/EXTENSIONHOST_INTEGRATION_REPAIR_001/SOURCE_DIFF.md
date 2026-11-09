# EXTENSIONHOST_INTEGRATION_REPAIR_001 — source diff specification

This is an implementation-ready diff description, not an applied patch.

| File/function | Before | Proposed after | Necessity |
|---|---|---|---|
| `Win32IDE_LocalServer.cpp` extension branch | Runtime route is present at `1117-1129`, but thin adapters also exist elsewhere | Make one canonical extension dispatch branch and assert/record selected owner | Prevent pre-launch interception |
| `HeadlessIDE_GuiRoutes.cpp:58-65` | Calls `HandleRoute` | Preserve call and add route-owner coverage | Keep headless and GUI paths aligned |
| `ProductGuiRouteAdapters.hpp:51-62` | Returns `product_thin`, `host_pid:0` for extension paths | Remove extension ownership from this adapter or make it unreachable for production extension routes | Eliminate silent fallback |
| CMake production target | ExtensionHost target exists in `SmokeE2EIPC.cmake`, but dependency/linkage is not established by current source inspection | Add runtime TUs to `RawrXD-Win32IDE`; add explicit worker target dependency and deployment | Ensure implementation reaches the candidate |
| `ProductExtensionRuntime_Host.cpp:34-49` | Relative-to-`ExeDir` string path; ad-hoc command line; no error capture | Canonical validated path, Windows quoting helper, immediate `GetLastError()` capture | Make launch deterministic and diagnosable |
| `ProductExtensionRuntime_Host.cpp:7-19` | Immediate `TerminateProcess` | Signal stop, bounded wait, terminate fallback, centralized cleanup | Avoid forced-only shutdown |
| `ExtensionHostWorker_main.cpp:4-12` | Creates stop event and waits forever | Parse launch identity, initialize IPC, emit ready, serve request/response, handle stop | Establish real readiness and protocol |
| `ProductExtensionRuntime_Activate.cpp:26-36` | Marks active after `CreateProcessA` succeeds | Mark active only after readiness handshake; return timeout/protocol error otherwise | Prevent false active state |

## Uncertainties to preserve

- The exact IPC transport is not selected by current source; named events alone are insufficient for real request/response.
- The historical `73368` defect is already repaired in candidate evidence, but current-tree target ownership must still be verified by a candidate configure/build after authorization.
- No source-only inspection can prove runtime readiness, process creation, or clean shutdown.

