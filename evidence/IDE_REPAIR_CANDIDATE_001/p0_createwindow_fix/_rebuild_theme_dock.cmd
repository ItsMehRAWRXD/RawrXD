@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (echo VCVARS_FAIL& exit /b 90)
cmake --build F:\rawrxd\build_tip_debug_rel --config RelWithDebInfo --target RawrXD-Win32IDE-Native-Ext -j 4
echo EXIT=%ERRORLEVEL%
