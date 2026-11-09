# Shutdown and wait inventory

## ExtensionHost lifecycle

`ProductExtensionRuntime_Host.cpp:24-36` signals the stop event, waits up to 2000 ms for the host process, then calls `TerminateProcess` on timeout and closes handles. Launch readiness waits up to 5000 ms at lines 102-107.

## IDE teardown

`Win32IDE_Core.cpp:1503-1533` handles `WM_CLOSE` synchronously, including save/settings work before `DestroyWindow`.

`Win32IDE_Core.cpp:1577-1636` handles `WM_DESTROY`, detaches JS hosts, destroys WebView2, stops terminal managers, shuts down the agentic browser, neutralizes child windows, and posts quit.

`Win32IDE_Core.cpp:1639-1647` handles `WM_NCDESTROY` and invokes `onDestroy`.

`Win32IDE_Core.cpp:4883-4960` performs final teardown and polls `m_activeDetachedThreads` for up to 3 seconds before proceeding. It then stops the local server, resets loaders, shuts down VS Code APIs, and unloads native extensions.

Potential blocking sites are classified only as candidates: save/settings, terminal stop, WebView/COM teardown, detached-thread polling, local-server stop, and extension-loader teardown. No root cause is assigned.
