# Dependency closure

## Source closure

`ProductExtensionRuntime.hpp` → `ProductExtensionRuntime_Internal.hpp` → the eight runtime implementation TUs → Windows/filesystem/stream/threading standard libraries. `ExtensionHostWorker_main.cpp` depends only on `<windows.h>` in the current implementation.

## Integration closure

`Win32IDE_LocalServer.cpp` and `HeadlessIDE_GuiRoutes.cpp` call `ProductExtensionRuntime::HandleRoute`; `HeadlessIDE_ToolRoutes.cpp` calls `ToolActivate`. `CMakeLists.txt` owns `RawrXD-Win32IDE`; `cmake/SmokeE2EIPC.cmake` defines a `RawrXD-ExtensionHost` target and companion copy command, but its production-target dependency is not established by this read-only comparison.

## Deployment closure

The worker must be emitted beside the candidate IDE executable because `ProductExtensionRuntime_Host.cpp` resolves `RawrXD-ExtensionHost.exe` under `ExeDir()`. No model, GPU, generated artifact, or frozen binary is part of this minimum closure.

## Stop decision

The closure is identifiable, but the candidate checkout is materially corrupted/sparse. Applying a baseline patch now would conflate restoring the checkout with source extraction. Recovery must first use a newly recreated or repaired candidate worktree from `273924f…`, then re-run this inventory.

