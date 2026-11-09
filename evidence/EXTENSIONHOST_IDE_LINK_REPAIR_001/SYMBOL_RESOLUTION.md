# Symbol resolution

The original 18 unresolved externals were eliminated. The rebuild compiled all five newly added translation units:

1. `Win32IDE_SidebarRuntime.cpp`
2. `Win32IDE_ChatWindowUI.cpp`
3. `Win32IDE_TasksDebugUI.cpp`
4. `Win32IDE_PathBCmdDiagSwarm.cpp`
5. `Win32IDE_CallStackSymbols.cpp`

The new final-link boundary exposes 7 unresolved `RawrXDChatWindow_*` symbols referenced by `Win32IDE_ChatWindowUI.cpp`:

- `RawrXDChatWindow_Create`
- `RawrXDChatWindow_Destroy`
- `RawrXDChatWindow_Show`
- `RawrXDChatWindow_Hide`
- `RawrXDChatWindow_SendMessage`
- `RawrXDChatWindow_Cancel`
- `RawrXDChatWindow_GetHwnd`

Their implementations exist in `src/win32app/Win32IDE_ChatWindow.cpp` at lines 858-926, but that translation unit is not present in the generated IDE build graph. The original 18-symbol defect is therefore resolved; the next blocker is another source-exists-not-linked dependency.
