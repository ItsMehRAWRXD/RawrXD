@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd\build_tip_ext_host_001
echo NINJA_START=%DATE% %TIME%
ninja RawrXD-Win32IDE-Native-Ext
echo NINJA_EXIT=%ERRORLEVEL%
echo NINJA_END=%DATE% %TIME%
exit /b %ERRORLEVEL%
