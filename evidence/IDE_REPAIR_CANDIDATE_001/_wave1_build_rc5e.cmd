@echo off
setlocal EnableExtensions
set LOG=F:\rawrxd_wave1_repair\evidence\IDE_REPAIR_CANDIDATE_001\build_rc5e.log
echo WAVE1_RC5E_BUILD_START %DATE% %TIME% > "%LOG%"

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >> "%LOG%" 2>&1
if errorlevel 1 (
  echo VCVARS_FAIL>> "%LOG%"
  exit /b 1
)

REM --- Build computer_use verify from tip build tree if present ---
set BUILD=F:\rawrxd\build_tip_debug_rel
if exist "%BUILD%\CMakeCache.txt" (
  cmake --build "%BUILD%" --config RelWithDebInfo --target rawrxd_computer_use_ide_verify -j 8 >> "%LOG%" 2>&1
  echo CU_VERIFY_BUILD_EXIT=%ERRORLEVEL%>> "%LOG%"
) else (
  echo NO_BUILD_TIP_CACHE>> "%LOG%"
)

REM --- Build deep2_agentic_loop via dedicated bat ---
call F:\rawrxd\tools\build_deep2_agentic_loop.bat >> "%LOG%" 2>&1
echo LOOP_BUILD_EXIT=%ERRORLEVEL%>> "%LOG%"

REM --- Stage package rc5e (do not touch RC4) ---
set PKG=F:\rawrxd\release\RawrXD-readiness-rc5e
if not exist "%PKG%" mkdir "%PKG%"
copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\" >> "%LOG%" 2>&1
copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\rawr.exe" "%PKG%\" >> "%LOG%" 2>&1
copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\settings.json" "%PKG%\" >> "%LOG%" 2>&1

if exist "F:\rawrxd\tools\deep2_agentic_loop.exe" (
  copy /Y "F:\rawrxd\tools\deep2_agentic_loop.exe" "%PKG%\deep2_agentic_loop.exe" >> "%LOG%" 2>&1
) else (
  echo LOOP_EXE_MISSING>> "%LOG%"
)

if exist "%BUILD%\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" (
  copy /Y "%BUILD%\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >> "%LOG%" 2>&1
) else if exist "%BUILD%\src\computer_use\tests\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" (
  copy /Y "%BUILD%\src\computer_use\tests\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >> "%LOG%" 2>&1
) else (
  echo CU_VERIFY_EXE_MISSING_TRYING_RC5B>> "%LOG%"
  if exist "F:\rawrxd\release\RawrXD-readiness-rc5b\rawrxd_computer_use_ide_verify.exe" (
    copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5b\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >> "%LOG%" 2>&1
  )
)

powershell -NoProfile -Command ^
  "$pkg='%PKG%'; Get-ChildItem $pkg -File | ForEach-Object { $h=(Get-FileHash $_.FullName -Algorithm SHA256).Hash; '{0}  {1}  {2}' -f $h,$_.Length,$_.Name }" ^
  > "%PKG%\SHA256.txt"

type "%PKG%\SHA256.txt" >> "%LOG%"
echo WAVE1_RC5E_BUILD_DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
