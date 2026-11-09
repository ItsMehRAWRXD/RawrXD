# Unresolved symbols

Source: `G:\~dev\rawrxd\evidence\EXTENSIONHOST_CANDIDATE_BUILD_001\BUILD_LOG.txt`, lines 2175-2215. There are 18 unique unresolved symbols; repeated references are not counted twice.

| # | Symbol | Referencing object | Definition found |
|---|---|---|---|
| 1 | `RawrXD_UI_ShowChatWindow` | `Win32IDE_Core.cpp.obj`, `Win32IDE_Commands.cpp.obj` | `src/win32app/Win32IDE_ChatWindowUI.cpp:45` |
| 2 | `RawrXD::Win32App::PathBCmdDiagSwarmBodyDone()` | Core, CommandFlight objects | `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp:66` |
| 3 | `RawrXD_UI_ListTasksForPicker` | `Win32IDE_Commands.cpp.obj` | `src/win32app/Win32IDE_TasksDebugUI.cpp:99` |
| 4 | `RawrXD_UI_RunTask` | `Win32IDE_Commands.cpp.obj` | `src/win32app/Win32IDE_TasksDebugUI.cpp:120` |
| 5 | `RawrXD_UI_ListLaunchConfigs` | `Win32IDE_Commands.cpp.obj` | `src/win32app/Win32IDE_TasksDebugUI.cpp:184` |
| 6 | `RawrXD_UI_StartDebugging` | `Win32IDE_Commands.cpp.obj` | `src/win32app/Win32IDE_TasksDebugUI.cpp:204` |
| 7 | `Win32IDE::destroySidebarRuntimeChildren(HWND*)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:45` |
| 8 | `Win32IDE::createGitHubView(HWND*)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:56` |
| 9 | `Win32IDE::createGitHubPullReleaseView(HWND*)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:68` |
| 10 | `Win32IDE::createAccountsView(HWND*)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:79` |
| 11 | `Win32IDE::createManageView(HWND*)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:90` |
| 12 | `Win32IDE::handleSidebarRuntimeCommand(int)` | `Win32IDE_Sidebar.cpp.obj` | `src/win32app/Win32IDE_SidebarRuntime.cpp:102` |
| 13 | `RawrXD::Win32App::EnsurePathBCmdDiagEngine(char const*)` | `Win32IDE_SubAgent.cpp.obj` | `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp:45` |
| 14 | `RawrXD::Win32App::PathBCmdDiagModelOpen()` | `Win32IDE_SubAgent.cpp.obj` | `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp:53` |
| 15 | `RawrXD::Win32App::PathBCmdDiagEngineBound()` | `Win32IDE_SubAgent.cpp.obj` | `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp:57` |
| 16 | `RawrXD::Win32App::PathBCmdDiagMarkSwarmBodyDone(unsigned)` | `Win32IDE_SubAgent.cpp.obj` | `src/win32app/Win32IDE_PathBCmdDiagSwarm.cpp:61` |
| 17 | `Win32IDE::initCallStackSymbols()` | `Win32IDE_Tier5Cosmetics.cpp.obj` | `src/win32app/Win32IDE_CallStackSymbols.cpp:292` |
| 18 | `Win32IDE::handleCallStackCommand(int)` | `Win32IDE_Tier5Cosmetics.cpp.obj` | `src/win32app/Win32IDE_CallStackSymbols.cpp:304` |

`LNK1120` is the aggregate failure, not an additional root symbol.
