@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
set ROOT=F:\~dev\rawrxd
set BDIR=%ROOT%\build-win32ide-p1
if exist "%BDIR%" rmdir /s /q "%BDIR%"
mkdir "%BDIR%" || exit /b 1
cd /d "%BDIR%" || exit /b 1
echo === CMAKE (Win32IDE-only, RawrEngine isolated) ===
cmake "%ROOT%" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -DRAWRXD_BUILD_WIN32IDE=ON ^
  -DRAWRXD_BUILD_RAWRENGINE=OFF ^
  -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=ON
if errorlevel 1 exit /b 1
echo === NINJA RawrXD-Win32IDE ===
ninja RawrXD-Win32IDE
exit /b %ERRORLEVEL%
