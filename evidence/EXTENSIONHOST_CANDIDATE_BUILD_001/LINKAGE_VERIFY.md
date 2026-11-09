# Linkage verification

Candidate build directory: `G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_001`

The generated `build.ninja` contains `ExtensionHostWorker_main.cpp` in the `RawrXD-ExtensionHost` target and the ProductExtensionRuntime translation units in the `RawrXD-Win32IDE` target. The worker target linked successfully at step 54/1433. The IDE target compiled the ExtensionHost runtime objects, including `ProductExtensionRuntime_Host.cpp`, but failed at the final link with 18 unrelated unresolved externals.

First demonstrated failure boundary: `RawrXD-Win32IDE.exe` final link, exit code 1120. No runtime execution was performed.

## Linker blockers

`RawrXD_UI_ShowChatWindow`, `RawrXD_UI_ListTasksForPicker`, `RawrXD_UI_RunTask`, `RawrXD_UI_ListLaunchConfigs`, `RawrXD_UI_StartDebugging`, `PathBCmdDiagSwarmBodyDone`, sidebar runtime methods, `EnsurePathBCmdDiagEngine`, `PathBCmdDiagModelOpen`, `PathBCmdDiagEngineBound`, `PathBCmdDiagMarkSwarmBodyDone`, and two `Win32IDE` call-stack methods.

These are the first build blockers observed; no corrective source change was authorized or applied.
