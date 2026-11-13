# CANDIDATE_RELINK — FOUR_PANEL_COMPLETION_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CANDIDATE_RELINK=FAIL_CLOSED
748B_CLOBBER=0
DIR=g:\~dev\rawrxd\build-win32ide-p1-candidate
```

## Attempt
```
ninja -v CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/Win32TerminalManager.cpp.obj
ninja -v bin/RawrXD-Win32IDE.exe
```
Log: `logs/candidate_relink.txt`

## Exact failure
1. Ninja invoked `cmake --regenerate-during-build -S rawrxd -B build-win32ide-p1-candidate`.
2. Reconfigure emitted `RAWRXD_IDE_TARGET_CONFIGURED=0` and `VERDICT=FAIL_IDE_NOT_BUILT` (CMakeLists warns: need `-DRAWRXD_BUILD_WIN32IDE=ON`).
3. No `bin\RawrXD-Win32IDE.exe` produced; directory remained PDB/DLL-only.
4. Regenerate ran long enough to stall the agent shell; incremental obj-only rebuild was not reached.

## Required next command (not run / not invented PASS)
```
cmake -S g:\~dev\rawrxd -B g:\~dev\rawrxd\build-win32ide-p1-candidate -DRAWRXD_BUILD_WIN32IDE=ON ...
ninja -C g:\~dev\rawrxd\build-win32ide-p1-candidate bin/RawrXD-Win32IDE.exe
```
Then hash the new EXE and bind TERMINAL/HWND gates to that SHA (never tip freeze 748B).

## Source already ready for absorb
`src/win32app/Win32TerminalManager.cpp/.h` capture fix (TERMINAL harness PASS).
