# Target graph verification

After reconfiguration, the generated Ninja graph contains all six repaired units:

- `Win32IDE_SidebarRuntime.cpp`
- `Win32IDE_ChatWindowUI.cpp`
- `Win32IDE_ChatWindow.cpp`
- `Win32IDE_TasksDebugUI.cpp`
- `Win32IDE_PathBCmdDiagSwarm.cpp`
- `Win32IDE_CallStackSymbols.cpp`

The build compiled `Win32IDE_ChatWindow.cpp.obj`, proving the new membership edge was active. No source outside the candidate CMake file was modified for this repair.
