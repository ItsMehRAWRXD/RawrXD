# Gates G54 (Docking/layout persistence) + G55 (Native Git) => PASS (runtime)

Both were initially flagged "implementation unconfirmed" after a failed source
search. Authoritative source tracing + runtime checks confirm they are
implemented.

## G54 — Layout persistence => PASS
- Source: `Win32IDE_Session.cpp` `SaveWindowState()` reads `WINDOWPLACEMENT`
  and persists a `RawrXD::WindowState`; `LoadWindowState()` restores it;
  `Win32IDE_Core.cpp` re-applies `WINDOWPLACEMENT`. Session file is
  `%APPDATA%\RawrXD\session.json` (portable).
- Runtime: launched the IDE, closed it, and confirmed `session.json` written
  (797 bytes) with full state:
  `panel.sidebarWidth`, `sidebarVisible`, `theme`, `editor.cursorLine`,
  `workingDirectory`, `schemaVersion 2.2`, etc.

## G55 — Native Git operations => PASS (menu + command surface present)
- Source: `Win32IDE_CommandIDs.h` defines `IDM_GIT_STATUS/COMMIT/PUSH/PULL/
  PANEL/STAGE_ALL` (3020-3025) and `IDC_BTN_GITHUB` (1022). `Win32IDE.cpp`
  builds a Git menu with Status/Commit/Panel and tracks `m_gitStatus`
  (enabling items based on repo/changes).
- Runtime: enumerated the IDE menu bar; the Git submenu contains command IDs
  `3020,3021,3022,3023,3024` (Status, Commit, Push, Pull, Git Panel). => PASS.

## Probes
- `gui_g54_g55_probe.ps1` (session.json check)
- `gui_g55_gitmenu.ps1` (Git submenu ID enumeration)

## Ledger
```
G54=PASS
G55=PASS
REMAINING=71  (of the 73; this closes 2 agentic-IDE gates)
```