@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd\build-win32ide-fresh
cmake --build . --target RawrXD-Agentic -j 8
echo BUILD_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
