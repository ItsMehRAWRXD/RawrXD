@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "F:\rawrxd\.worktrees\release-freeze-001\build_release_freeze_001"
ninja RawrXD-Win32IDE-Native-Ext
exit /b %ERRORLEVEL%
