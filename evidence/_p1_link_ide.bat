@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "F:\~dev\rawrxd\build-win32ide-p1" || exit /b 1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM mspdbsrv.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
del /f /q "bin\RawrXD-Win32IDE.pdb" >nul 2>&1
del /f /q "bin\RawrXD-Win32IDE.exe" >nul 2>&1
echo === dry-run remaining ===
ninja -n RawrXD-Win32IDE 2>&1 | findstr /c:"Linking" /c:"main_win32" /c:"still dirty"
echo === link-only attempt via ninja -j1 with restat ===
ninja -t restat
ninja -j 1 RawrXD-Win32IDE
set RC=%ERRORLEVEL%
echo RC=%RC%
if exist bin\RawrXD-Win32IDE.exe (
  echo EXE_OK
  findstr /m /c:"repost_after_startup_pumps" bin\RawrXD-Win32IDE.exe && echo HAS_REPOST || echo NO_REPOST
) else (
  echo EXE_MISSING
)
exit /b %RC%
