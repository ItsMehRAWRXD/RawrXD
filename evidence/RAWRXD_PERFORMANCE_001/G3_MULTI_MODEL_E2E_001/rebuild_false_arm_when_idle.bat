@echo off
setlocal
set EV=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001
set RUNNER=9484
:wait
tasklist /FI "PID eq %RUNNER%" 2>nul | find "%RUNNER%" >nul
if not errorlevel 1 (
  timeout /t 60 /nobreak >nul
  goto wait
)
REM Also wait if ninja/cl holding build-fd locks from other agents ? brief settle
timeout /t 15 /nobreak >nul
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\build-fd
echo REBUILD_START %DATE% %TIME%>> "%EV%\FALSE_ARM_REBUILD.txt"
ninja RawrXD-Win32IDE > "%EV%\false_arm_rebuild.log" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>> "%EV%\FALSE_ARM_REBUILD.txt"
echo REBUILD_END %DATE% %TIME%>> "%EV%\FALSE_ARM_REBUILD.txt"
