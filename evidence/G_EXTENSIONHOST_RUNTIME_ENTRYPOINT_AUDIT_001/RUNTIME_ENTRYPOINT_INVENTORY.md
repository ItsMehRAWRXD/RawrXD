# Runtime entrypoint inventory

## Production-reachable UI entrypoint

The Extensions sidebar creates an `Activate` button in `src/win32app/Win32IDE_Sidebar.cpp:2474-2500` with control ID `IDC_EXT_INSTALL`. Its sidebar window procedure handles that ID at approximately `src/win32app/Win32IDE_Sidebar.cpp:545-570` and calls `Win32IDE::activateExtension(selectedId)`. A double-click on the extension list reaches the same method at approximately lines 620-630.

`Win32IDE::activateExtension` at `Win32IDE_Sidebar.cpp:2600-2615` sets ProductExtensionRuntime roots and calls `ProductExtensionRuntime::Activate(extensionId)`.

`ProductExtensionRuntime::Activate` at `ProductExtensionRuntime_Activate.cpp:5-36` scans and validates the extension, rejects missing/disabled records, then calls `SpawnHostUnlocked`.

`SpawnHostUnlocked` at `ProductExtensionRuntime_Host.cpp:60-107` creates the ready/stop events, constructs the command line, calls `CreateProcessA`, and waits up to 5000 ms for readiness.

## Other entrypoints

The local HTTP server routes `/api/extensions...` to `ProductExtensionRuntime::HandleRoute` at `Win32IDE_LocalServer.cpp:1127-1129`; tool `extension.activate` reaches `ProductExtensionRuntime::ToolActivate` at approximately `Win32IDE_LocalServer.cpp:5475-5480`. These are production server/tool entrypoints, not generic menu commands.
