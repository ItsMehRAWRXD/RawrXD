@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-fresh" || exit /b 1
echo === CMAKE ===
cmake "F:\~dev\rawrxd" -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=ON
if errorlevel 1 exit /b 1
echo === NINJA RawrXD-Win32IDE ===
ninja RawrXD-Win32IDE
exit /b %ERRORLEVEL%
