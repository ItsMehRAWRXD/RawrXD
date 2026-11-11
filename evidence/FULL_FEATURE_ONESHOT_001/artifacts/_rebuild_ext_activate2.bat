@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "F:\rawrxd\build_tip_ext_host_001"
ninja RawrXD-Win32IDE-Native-Ext > "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_EXT_WIRE_BUILD3.log" 2>&1
echo NINJA_RC=%ERRORLEVEL%
exit /b %ERRORLEVEL%
