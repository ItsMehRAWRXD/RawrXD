# CMake/link graph

Candidate CMake source list: `G:\~dev\rawrxd-ext-candidate-clean\CMakeLists.txt`.

The IDE list includes `Win32IDE_Sidebar.cpp` at line 5722 and `Win32IDE_Tier5Cosmetics.cpp` at line 6351, but does not include the implementation units below. The generated `build_ext_host_001\build.ninja` likewise has no build edge for them:

```text
src/win32app/Win32IDE_ChatWindowUI.cpp
src/win32app/Win32IDE_TasksDebugUI.cpp
src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp
src/win32app/Win32IDE_SidebarRuntime.cpp
src/win32app/Win32IDE_CallStackSymbols.cpp
```

The missing five source files account for all 18 unresolved symbols. This is one shared CMake target-membership defect, not 18 independent implementation defects. No library omission is indicated because the definitions are ordinary translation-unit symbols in the candidate source tree.
