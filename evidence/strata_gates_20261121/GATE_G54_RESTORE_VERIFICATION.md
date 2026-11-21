# Gate G54 — Layout persistence => PARTIAL (window geometry NOT restored)

## What persists (confirmed)
- `%APPDATA%\RawrXD\session.json` (797 B) is written with editor state
  (cursor, scroll, selection, syntax language), panel state
  (sidebarWidth, sidebarVisible, activeTab, maximized), theme, and
  workingDirectory. => editor/panel/theme persistence works.

## What does NOT persist (this test)
- **Window geometry (position/size) is not restored.** A move-and-restore
  runtime test:
  1. Launched the IDE, `MoveWindow` to (123,77) size 900x640.
  2. `WM_CLOSE` (which calls `SaveWindowState` -> `GetSettings().SetWindowState`
     -> `GetSettings().Shutdown`).
  3. Relaunched.
  4. Observed restored rect = **(286,286,1566,1086)** (1280x800), NOT (123,77,900x640).
- Searching all of `%APPDATA%\RawrXD` (`session.json`, `settings.json`,
  `settings.ini`) and `F:\rawrxd\.rawrxd` finds **no window geometry keys**
  (`windowX/Y/Width/Height`). So `Settings::SetWindowState` does not serialize
  window geometry to any discoverable file, and `LoadWindowState` restores from
  an in-memory settings object that is empty on a fresh process.

## Conclusion
G54 is **PARTIAL**: editor/panel/theme state persist and restore, but
**window position/size do not persist across restarts**. The sprint's required
acceptance ("move/resize, exit, relaunch, compare restored state") is NOT met for
window geometry.

## Root cause (to fix)
`Settings::SetWindowState/GetWindowState` need to serialize the window
geometry to the settings file (e.g. `settings.json` or `session.json`) and
`LoadWindowState` must apply it at window creation. Currently the geometry is
lost between processes.

## Evidence files
- `gui_g54_restore_probe.ps1` (move/exit/relaunch/compare)
- Observed: `SET_RECT=(123,77,1023,717)`, `RESTORED_RECT=(286,286,1566,1086)`,
  `G54_RESTORE=FAIL`.

## Ledger
```
G54=PARTIAL  (editor/panel/theme persist; window geometry does NOT restore)
```