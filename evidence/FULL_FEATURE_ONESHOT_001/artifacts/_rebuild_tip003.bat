@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd\build_tip_ext_host_001
if errorlevel 1 exit /b 92
ninja RawrXD-Win32IDE-Native-Ext > "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_EXT_WIRE_BUILD5.log" 2>&1
set RC=%ERRORLEVEL%
echo NINJA_RC=%RC%
exit /b %RC%
