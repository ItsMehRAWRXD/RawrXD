@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d G:\~dev\rawrxd\build_p1pra_win32ide
echo BUILD_START
cmake --build . --target RawrXD-Win32IDE -j 8
echo BUILD_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
