@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
if errorlevel 1 exit /b 92
cmake -S F:\rawrxd -B F:\rawrxd\build_tip_debug_001 -G Ninja -DRAWRXD_NATIVE_IDE_EXT=ON > F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_DEBUG_CMAKE.log 2>&1
if errorlevel 1 exit /b 94
cd /d F:\rawrxd\build_tip_debug_001
ninja debuggee_fixture debug_backend_verify RawrXD-Win32IDE-Native-Ext > F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_DEBUG_BUILD.log 2>&1
set RC=%ERRORLEVEL%
echo NINJA_RC=%RC%
exit /b %RC%
