# Source call graph

```text
Extensions sidebar Activate button or extension-list double-click
  -> sidebar content WndProc (Win32IDE_Sidebar.cpp:545-570 / 620-630)
  -> Win32IDE::activateExtension (Win32IDE_Sidebar.cpp:2600-2615)
  -> ProductExtensionRuntime::SetRoots
  -> ProductExtensionRuntime::Activate (ProductExtensionRuntime_Activate.cpp:5-36)
  -> ScanUnlocked / enabled-record validation
  -> SpawnHostUnlocked (ProductExtensionRuntime_Host.cpp:60-107)
  -> CreateProcessA
  -> WaitForSingleObject(readyEvent, 5000)
```

Classification: `REACHABLE_STATIC`. This proves a complete source-level route, not physical execution.

Separate server route:

```text
LocalServer /api/extensions request
  -> Win32IDE_LocalServer.cpp:1127-1129
  -> ProductExtensionRuntime::HandleRoute
```

Separate tool route:

```text
extension.activate tool
  -> Win32IDE_LocalServer.cpp:5475-5480
  -> ProductExtensionRuntime::ToolActivate
  -> ProductExtensionRuntime::Activate
```
