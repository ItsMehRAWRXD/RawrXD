@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd\build-win32ide-fresh
cmake F:\~dev\rawrxd -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=ON
echo RECONFIGURE_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
cmake --build . --target RawrXD-Win32IDE -j 8
echo BUILD_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%