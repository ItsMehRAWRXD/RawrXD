@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-p1" || exit /b 1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM mspdbsrv.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
del /f /q "bin\RawrXD-Win32IDE.pdb" >nul 2>&1
echo building main_win32 + link
ninja -j 1 CMakeFiles/RawrXD-Win32IDE.dir/src/win32app/main_win32.cpp.obj
if errorlevel 1 exit /b 1
ninja -j 1 RawrXD-Win32IDE
set RC=%ERRORLEVEL%
echo RC=%RC%
if exist bin\RawrXD-Win32IDE.exe (echo EXE_OK) else (echo EXE_MISSING)
exit /b %RC%
