@echo off
REM G01-04 attempt 2: private tree with RAWRXD_BUILD_WIN32IDE=ON (build_ninja has OFF)
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
echo ==== G01-04 GUI REBUILD ATTEMPT2 ====
echo HOST=%COMPUTERNAME%
echo TIME_START=%DATE% %TIME%
git rev-parse HEAD
git rev-parse --abbrev-ref HEAD
echo FREEZE_PIN=dde963941aa4b7647f94aafaa390f5e2eed72511
echo ATTEMPT1_COMMAND=cmake --build build_ninja --target RawrXD-Win32IDE --config Release
echo ATTEMPT1_EXIT=1
echo ATTEMPT1_BLOCKER=ninja: error: unknown target 'RawrXD-Win32IDE' (RAWRXD_BUILD_WIN32IDE=OFF in build_ninja)
echo ATTEMPT2_COMMAND=cmake --build build_win32ide --target RawrXD-Win32IDE --config Release
echo ATTEMPT2_DIR=build_win32ide RAWRXD_BUILD_WIN32IDE=ON private cand; tip build_ninja\bin untouched
cmake --build build_win32ide --target RawrXD-Win32IDE --config Release
set EC=%ERRORLEVEL%
echo TIME_END=%DATE% %TIME%
echo BUILD_EXIT=%EC%
if exist build_win32ide\bin\RawrXD-Win32IDE.exe (
  powershell -NoProfile -Command "(Get-FileHash build_win32ide\bin\RawrXD-Win32IDE.exe -Algorithm SHA256).Hash"
) else (
  echo EXE_ABSENT=1
)
if exist build_ninja\bin\RawrXD-Win32IDE.exe (
  powershell -NoProfile -Command "Write-Output ('TIP_SHA256=' + (Get-FileHash build_ninja\bin\RawrXD-Win32IDE.exe -Algorithm SHA256).Hash)"
)
if exist build_ninja\bin\tip_land_6754616E.exe (
  powershell -NoProfile -Command "Write-Output ('TIP_RO_SHA256=' + (Get-FileHash build_ninja\bin\tip_land_6754616E.exe -Algorithm SHA256).Hash)"
)
exit /b %EC%
