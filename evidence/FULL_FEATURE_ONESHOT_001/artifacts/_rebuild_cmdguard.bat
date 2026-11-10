@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
ninja -C "F:\rawrxd\build_tip_ext_host_001" RawrXD-Win32IDE-Native-Ext
exit /b %ERRORLEVEL%
