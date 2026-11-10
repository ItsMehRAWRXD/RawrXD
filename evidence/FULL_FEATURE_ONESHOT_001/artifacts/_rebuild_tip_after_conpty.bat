@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd
ninja -C "F:\rawrxd\build_tip_ext_host_001" CMakeFiles/RawrXD-Win32IDE-Native-Ext.dir/src/win32app/Win32TerminalManager.cpp.obj
if errorlevel 1 exit /b 11
ninja -C "F:\rawrxd\build_tip_ext_host_001" RawrXD-Win32IDE-Native-Ext
exit /b %ERRORLEVEL%
