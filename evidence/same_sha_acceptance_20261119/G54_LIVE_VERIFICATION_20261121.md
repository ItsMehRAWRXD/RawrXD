# G54 — live serializer verification (2026-11-21)

## Implementation (active source)
- `Win32IDE::saveIdeSession()` (`src/win32app/Win32IDE_FileOps.cpp`) now writes
  `root["window"] = {x,y,width,height,maximized}` from
  `GetWindowPlacement(m_hwndMain).rcNormalPosition` (workspace coords).
- `Win32IDE::loadIdeSession()` restores via `SetWindowPlacement()`
  (DPI-aware, maximized state), backward-compatible when `window` is absent.
- Build: `RawrXD-Win32IDE-Native` PASS.
- Patch: `patch_g54_live_serializer.py` (assertion-checked).

## Profile isolation
- `RawrXD::NativeProfile::directory()` = `%LOCALAPPDATA%\RawrXD` by default,
  overridable via `RAWRXD_USER_DATA_DIR` / `--user-data-dir`
  (`src/win32app/NativeProfilePath.h`).
- Probe uses isolated profile `evidence/g54_profile`; session file
  `evidence/g54_profile/ide_session.json`.

## Runtime results (`gui_g54_profile_probe.ps1`)
```
SET_RECT=(338,338,1618,1138)
N1_EXIT=TIMEOUT
SAVED_WINDOW x=338 y=338 w=1280 h=800 max=False
RESTORED_RECT=(338,338,1618,1138)
NORMAL_RESTORE=PASS
M1_ZOOMED=True
M1_SAVED_MAX=False
M2_ZOOMED=False
MAXIMIZED_RESTORE=FAIL
```

## Assessment
- **NORMAL_RESTORE=PASS** — geometry is persisted to `ide_session.json` and
  restored on relaunch. The live serializer works.
- **MAXIMIZED_RESTORE=FAIL** — with the window maximized (`IsZoomed=True`),
  the saved `maximized` flag is `false`. Likely cause: `WINDOWPLACEMENT.showCmd`
  is not `SW_SHOWMAXIMIZED` at save time (the IDE may normalize the window
  state during layout), or the maximize is applied after the save. Needs a
  targeted fix in `saveIdeSession()` (e.g., also consult `IsZoomed(m_hwndMain)`)
  and verification.
- **N1_EXIT=TIMEOUT** — the process did not exit within 12 s although the
  session was written; exit code and full teardown time need measurement
  (possibly worker-thread joins).

## Remaining G54 work
1. Fix the maximized flag: `maximized = (wp.showCmd == SW_SHOWMAXIMIZED) || IsZoomed(m_hwndMain)`.
2. Re-verify with a distinctive rect (e.g., 123,77,900x640) and a maximized case.
3. Measure natural exit time / exit code (allow longer wait).
4. Legacy session without `window` key loads (backward compatible — implemented).
5. Commit the live patch + probe + evidence (this file).

## Dead-file patches (superseded)
- `Win32IDE_Session.cpp` (commit `49feb27d28`) and `Win32IDE_Core.cpp`
  (uncommitted `[CLOSE]` instrumentation) are in translation units **not in
  the vcxproj** → no runtime effect. Kept for history; not part of the fix.