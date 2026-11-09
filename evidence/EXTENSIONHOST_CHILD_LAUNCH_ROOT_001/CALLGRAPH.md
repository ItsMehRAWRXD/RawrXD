# EXTENSIONHOST_CHILD_LAUNCH_ROOT_001 — call graph

## Request-to-child path

1. `Win32IDE_LocalServer::handleClient` selects extension requests and calls `ProductExtensionRuntime::HandleRoute` after setting roots: `src/win32app/Win32IDE_LocalServer.cpp:1117-1129`.
2. `HeadlessIDE::routeGuiProductRequest` sets roots and forwards to `ProductExtensionRuntime::HandleRoute`: `src/win32app/HeadlessIDE_GuiRoutes.cpp:37-65`.
3. `ProductExtensionRuntime::HandleRoute` dispatches POST activation to `Activate`: `src/win32app/ProductExtensionRuntime_Api.cpp:30-55`.
4. `ProductExtensionRuntime::Activate` locks state, scans, resolves the extension record, verifies enabled state, and calls `SpawnHostUnlocked`: `src/win32app/ProductExtensionRuntime_Activate.cpp:6-36`.
5. `SpawnHostUnlocked` checks an existing process, resolves `ExeDir()/RawrXD-ExtensionHost.exe`, builds the command line, and calls `CreateProcessA`: `src/win32app/ProductExtensionRuntime_Host.cpp:21-57`.
6. The child entry point is `WinMain`; it creates `Local\\RawrXD_ExtensionHost_Stop` and waits indefinitely: `src/win32app/ExtensionHostWorker_main.cpp:4-12`.

## Historical bypass path

`ProductGuiRoutes::extensionsJson` directly returns thin responses for list/status/POST extension operations, including `host_pid:0`: `src/win32app/ProductGuiRouteAdapters.hpp:51-62`. This is the earliest demonstrated boundary for candidate `73368`: the real runtime and process launcher are bypassed.

## Launch parameters

`CreateProcessA` receives:

- application name: `hostExe` (`ProductExtensionRuntime_Host.cpp:46`)
- command line: quoted executable, unquoted `rec.id`, quoted `rec.path` (`:42-45`)
- security attributes: null
- handle inheritance: `FALSE`
- creation flags: `CREATE_NO_WINDOW`
- environment: inherited (`nullptr`)
- current directory: `ExeDir()` (`:46-49`)

No pipe handles, IPC endpoint, handshake token, readiness event, or timeout is passed in this launch path.

