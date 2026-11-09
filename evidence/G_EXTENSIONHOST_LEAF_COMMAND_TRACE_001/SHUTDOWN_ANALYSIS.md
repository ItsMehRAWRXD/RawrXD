# Shutdown analysis

The controlled run's `Alt+F4` did not terminate the test-owned IDE. The source close path is synchronous:

- `WM_CLOSE` at `src/win32app/Win32IDE_Core.cpp:1503-1533` calls `SaveWindowState`, settings shutdown, and `DestroyWindow` after `promptSaveChanges()`.
- `WM_DESTROY` at `Win32IDE_Core.cpp:1577-1636` stops watchdogs/terminals, detaches JS hosts, destroys WebView2, neutralizes child windows, and posts quit.
- `WM_NCDESTROY` at `Win32IDE_Core.cpp:1639-1647` calls `onDestroy()` and posts quit again.
- `onDestroy()` at `Win32IDE_Core.cpp:4883-4960` waits up to three seconds for detached threads, then performs local-server, loader, JS-host, extension-loader, and core-runtime teardown.

The observed forced cleanup does not identify which close step failed because no close breadcrumb, thread stack, or wait chain was captured. The source shows plausible blocking regions, especially the detached-thread polling and extension/runtime teardown, but this is hypothesis only. The separate `ProductExtensionRuntime_Host.cpp:24-36` graceful child shutdown path was not reached or observed.
