@echo off
setlocal EnableExtensions EnableDelayedExpansion
set LOG=F:\rawrxd_wave1_repair\evidence\IDE_REPAIR_CANDIDATE_001\build_rc5e2.log
echo WAVE1_RC5E2_START %DATE% %TIME%>"%LOG%"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
call "%VCVARS%" x64 >>"%LOG%" 2>&1
echo AFTER_VCVARS err=!ERRORLEVEL!>>"%LOG%"

set BUILD=F:\rawrxd\build_tip_debug_rel
echo BUILD_DIR=%BUILD%>>"%LOG%"
if exist "%BUILD%\CMakeCache.txt" (
  echo HAS_CMAKE_CACHE=1>>"%LOG%"
  echo START_CU_VERIFY_BUILD>>"%LOG%"
  cmake --build "%BUILD%" --config RelWithDebInfo --target rawrxd_computer_use rawrxd_computer_use_ide_verify -j 4 >>"%LOG%" 2>&1
  echo CU_VERIFY_BUILD_EXIT=!ERRORLEVEL!>>"%LOG%"
) else (
  echo HAS_CMAKE_CACHE=0>>"%LOG%"
)

echo START_STANDALONE_CU_VERIFY>>"%LOG%"
cl /nologo /std:c++20 /EHsc /O2 /W3 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
  /I F:\rawrxd\src\computer_use /I F:\rawrxd\src ^
  F:\rawrxd\src\computer_use\tests\ComputerUseIdeVerify.cpp ^
  F:\rawrxd\src\computer_use\ComputerUse.cpp ^
  F:\rawrxd\src\computer_use\ScreenCapture.cpp ^
  F:\rawrxd\src\computer_use\ComputerUseBridge.cpp ^
  F:\rawrxd\src\computer_use\ComputerUseParse.cpp ^
  /FeF:\rawrxd\tools\rawrxd_computer_use_ide_verify.exe ^
  /FoF:\rawrxd\tools\obj_cu_verify\ ^
  user32.lib gdi32.lib >>"%LOG%" 2>&1
echo STANDALONE_CU_EXIT=!ERRORLEVEL!>>"%LOG%"

echo START_LOOP_BUILD>>"%LOG%"
if not exist F:\rawrxd\tools\obj_agentic_loop mkdir F:\rawrxd\tools\obj_agentic_loop
REM Prefer existing nlohmann / winhttp path used by tip builds; fall back to bat.
where cl >>"%LOG%" 2>&1
call F:\rawrxd\tools\build_deep2_agentic_loop.bat >>"%LOG%" 2>&1
echo LOOP_BUILD_EXIT=!ERRORLEVEL!>>"%LOG%"

set PKG=F:\rawrxd\release\RawrXD-readiness-rc5e
if not exist "%PKG%" mkdir "%PKG%"
copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\" >>"%LOG%" 2>&1
copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\rawr.exe" "%PKG%\" >>"%LOG%" 2>&1
if exist "F:\rawrxd\release\RawrXD-readiness-rc5\settings.json" copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5\settings.json" "%PKG%\" >>"%LOG%" 2>&1
if exist "F:\rawrxd\tools\deep2_agentic_loop.exe" (
  copy /Y "F:\rawrxd\tools\deep2_agentic_loop.exe" "%PKG%\deep2_agentic_loop.exe" >>"%LOG%" 2>&1
) else (
  echo LOOP_EXE_MISSING>>"%LOG%"
)
if exist "F:\rawrxd\tools\rawrxd_computer_use_ide_verify.exe" (
  copy /Y "F:\rawrxd\tools\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >>"%LOG%" 2>&1
) else if exist "%BUILD%\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" (
  copy /Y "%BUILD%\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >>"%LOG%" 2>&1
) else if exist "%BUILD%\src\computer_use\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" (
  copy /Y "%BUILD%\src\computer_use\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >>"%LOG%" 2>&1
) else if exist "F:\rawrxd\release\RawrXD-readiness-rc5b\rawrxd_computer_use_ide_verify.exe" (
  echo FALLBACK_RC5B_CU>>"%LOG%"
  copy /Y "F:\rawrxd\release\RawrXD-readiness-rc5b\rawrxd_computer_use_ide_verify.exe" "%PKG%\" >>"%LOG%" 2>&1
) else (
  echo CU_VERIFY_MISSING>>"%LOG%"
)

echo.>"%PKG%\SHA256.txt"
for %%F in ("%PKG%\*.*") do (
  if /I not "%%~nxF"=="SHA256.txt" (
    certutil -hashfile "%%F" SHA256 | findstr /v ":" | findstr /v "CertUtil" >>"%PKG%\SHA256.tmp"
    for /f "usebackq delims=" %%H in ("%PKG%\SHA256.tmp") do (
      echo %%H  %%~zF  %%~nxF>>"%PKG%\SHA256.txt"
    )
    del "%PKG%\SHA256.tmp" >nul 2>&1
  )
)
type "%PKG%\SHA256.txt">>"%LOG%"
echo WAVE1_RC5E2_DONE %DATE% %TIME%>>"%LOG%"
exit /b 0
