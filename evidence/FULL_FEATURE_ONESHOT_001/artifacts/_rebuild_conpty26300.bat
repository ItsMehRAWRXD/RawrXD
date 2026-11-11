@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd
cmake --build "F:\rawrxd\build_tip_ext_host_001" --target RawrXD-Win32IDE-Native-Ext -j 4
exit /b %ERRORLEVEL%
