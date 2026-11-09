# Minimal patch plan

Candidate-only CMake change: add exactly these five existing source files to the `RawrXD-Win32IDE` source list:

1. `src/win32app/Win32IDE_ChatWindowUI.cpp`
2. `src/win32app/Win32IDE_TasksDebugUI.cpp`
3. `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp`
4. `src/win32app/Win32IDE_SidebarRuntime.cpp`
5. `src/win32app/Win32IDE_CallStackSymbols.cpp`

Do not add stubs, dummy definitions, history snapshots, or unrelated source. Preserve the four-file ExtensionHost patch unchanged.

Required verification after separate authorization:

- clean candidate configure/build;
- confirm all five files produce IDE object edges;
- confirm the 18 unresolved symbols disappear;
- verify worker deployment beside the successfully linked IDE;
- do not launch executables in the linkage repair gate.
