@echo off
REM G01-04 Win32 GUI rebuild attempt — private cand; tip 6754616E RO protected separately
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
echo ==== G01-04 GUI REBUILD START ====
echo HOST=%COMPUTERNAME%
echo TIME_START=%DATE% %TIME%
git rev-parse HEAD
git rev-parse --abbrev-ref HEAD
echo FREEZE_PIN=dde963941aa4b7647f94aafaa390f5e2eed72511
echo COMMAND=cmake --build build_ninja --target RawrXD-Win32IDE --config Release
echo NOTE=build_gui.bat targets RawrXD-IDE (absent); using RawrXD-Win32IDE on ninja tree
echo TIP_RO_COPY=build_ninja\bin\tip_land_6754616E.exe
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
