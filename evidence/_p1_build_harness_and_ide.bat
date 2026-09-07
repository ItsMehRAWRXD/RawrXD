@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-p1" || exit /b 1
ninja -j 4 p1_cpu_loadmodel_harness
if errorlevel 1 exit /b 1
ninja -j 2 RawrXD-Win32IDE
exit /b %ERRORLEVEL%
