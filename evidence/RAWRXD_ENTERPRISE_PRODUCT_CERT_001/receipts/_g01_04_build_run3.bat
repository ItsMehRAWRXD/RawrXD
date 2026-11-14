@echo off
REM G01-04 attempt 3: reconfigure build_ninja with WIN32IDE=ON; private cand; tip RO restored after
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
echo ==== G01-04 GUI REBUILD ATTEMPT3 ====
echo HOST=%COMPUTERNAME%
echo TIME_START=%DATE% %TIME%
git rev-parse HEAD
git rev-parse --abbrev-ref HEAD
echo FREEZE_PIN=dde963941aa4b7647f94aafaa390f5e2eed72511
echo PRIOR_A1=build_ninja target unknown RAWRXD_BUILD_WIN32IDE=OFF EXIT=1
echo PRIOR_A2=build_win32ide ninja path C:\Users\HiH8e\...\ninja.exe missing EXIT=1
echo A3_RECONFIG=cmake -S . -B build_ninja -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON
echo A3_BUILD=cmake --build build_ninja --target RawrXD-Win32IDE --config Release
echo TIP_RO=build_ninja\bin\tip_land_6754616E.exe

cmake -S . -B build_ninja -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON
set RC=%ERRORLEVEL%
echo RECONFIG_EXIT=%RC%
if %RC% NEQ 0 (
  echo TIME_END=%DATE% %TIME%
  echo BUILD_EXIT=%RC%
  echo BLOCKER=cmake reconfigure with RAWRXD_BUILD_WIN32IDE=ON failed
  exit /b %RC%
)

cmake --build build_ninja --target RawrXD-Win32IDE --config Release
set EC=%ERRORLEVEL%
echo TIME_END=%DATE% %TIME%
echo BUILD_EXIT=%EC%

if exist build_ninja\bin\RawrXD-Win32IDE.exe (
  powershell -NoProfile -Command "(Get-FileHash build_ninja\bin\RawrXD-Win32IDE.exe -Algorithm SHA256).Hash"
) else (
  echo EXE_ABSENT=1
)
if exist build_ninja\bin\tip_land_6754616E.exe (
  powershell -NoProfile -Command "Write-Output ('TIP_RO_SHA256=' + (Get-FileHash build_ninja\bin\tip_land_6754616E.exe -Algorithm SHA256).Hash)"
)
exit /b %EC%
