@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd\build-win32ide-fresh
cmake --build . --target RawrXD-Win32IDE -j 2
echo BUILD_EXIT=%ERRORLEVEL%
if exist bin\RawrXD-Win32IDE.exe (
  for %%I in (bin\RawrXD-Win32IDE.exe) do echo EXE_SIZE=%%~zI EXE_TIME=%%~tI
)
exit /b %ERRORLEVEL%