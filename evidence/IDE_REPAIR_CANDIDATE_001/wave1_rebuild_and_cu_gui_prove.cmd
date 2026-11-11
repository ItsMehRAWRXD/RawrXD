@echo off
setlocal EnableExtensions EnableDelayedExpansion
set EVID=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\cu_gui_e2e_003
set BT=F:\rawrxd\build_tip_debug_rel
set PKG=F:\rawrxd\release\RawrXD-readiness-rc5b
set LOG=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\wave1_rebuild_prove.log
mkdir "%EVID%" 2>nul
echo WAVE1_REBUILD_START %DATE% %TIME%> "%LOG%"
echo UTC=%DATE% %TIME%> "%EVID%\BUILD_START.txt"
echo PROMOTE=0>> "%EVID%\BUILD_START.txt"

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo FIRST_FAILURE_CLASS=VCVARS_FAIL> "%EVID%\RECEIPT.txt"
  exit /b 90
)
echo INCLUDE=%INCLUDE%>> "%LOG%"

cmake --build "%BT%" --config RelWithDebInfo --target rawrxd_computer_use --target rawrxd_computer_use_ide_verify --target RawrXD-Win32IDE-Native-Ext -j 4 >> "%LOG%" 2>&1
set BUILD_EXT=!ERRORLEVEL!
echo BUILD_EXT_EXIT=!BUILD_EXT!>> "%LOG%"

REM Also try Release CLI if present
cmake --build "%BT%" --config RelWithDebInfo --target RawrXD-CLI-V2 -j 4 >> "%LOG%" 2>&1
set BUILD_CLI=!ERRORLEVEL!
echo BUILD_CLI_EXIT=!BUILD_CLI!>> "%LOG%"

if not "!BUILD_EXT!"=="0" (
  echo FIRST_FAILURE_CLASS=BUILD_FAIL> "%EVID%\RECEIPT.txt"
  echo See wave1_rebuild_prove.log>> "%EVID%\RECEIPT.txt"
  exit /b 1
)

set EXT=
for %%P in (
  "%BT%\bin\RawrXD-Win32IDE-Native-Ext.exe"
  "%BT%\src\win32app\RelWithDebInfo\RawrXD-Win32IDE-Native-Ext.exe"
  "%BT%\RelWithDebInfo\RawrXD-Win32IDE-Native-Ext.exe"
  "%BT%\bin-msvc\RawrXD-Win32IDE-Native-Ext.exe"
) do if exist %%~P set EXT=%%~P

set VERIFY=
for %%P in (
  "%BT%\src\computer_use\rawrxd_computer_use_ide_verify.exe"
  "%BT%\src\computer_use\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe"
  "%BT%\RelWithDebInfo\rawrxd_computer_use_ide_verify.exe"
) do if exist %%~P set VERIFY=%%~P

set RAWR=
for %%P in (
  "%BT%\bin\rawr.exe"
  "%BT%\RelWithDebInfo\rawr.exe"
  "%BT%\bin-msvc\rawr.exe"
  "F:\rawrxd\release\RawrXD-readiness-rc5\rawr.exe"
) do if exist %%~P set RAWR=%%~P

echo EXT=!EXT!>> "%LOG%"
echo VERIFY=!VERIFY!>> "%LOG%"
echo RAWR=!RAWR!>> "%LOG%"

if "!EXT!"=="" (
  echo FIRST_FAILURE_CLASS=EXT_BINARY_ABSENT> "%EVID%\RECEIPT.txt"
  exit /b 2
)

copy /Y "!EXT!" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%" 2>&1
if not "!VERIFY!"=="" copy /Y "!VERIFY!" "%PKG%\rawrxd_computer_use_ide_verify.exe" >> "%LOG%" 2>&1
if not "!RAWR!"=="" copy /Y "!RAWR!" "%PKG%\rawr.exe" >> "%LOG%" 2>&1

certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%EVID%\EXT_SHA.txt"
if exist "%PKG%\rawrxd_computer_use_ide_verify.exe" certutil -hashfile "%PKG%\rawrxd_computer_use_ide_verify.exe" SHA256 > "%EVID%\VERIFY_SHA.txt"
if exist "%PKG%\rawr.exe" certutil -hashfile "%PKG%\rawr.exe" SHA256 > "%EVID%\RAWR_SHA.txt"

REM Refresh package SHA256.txt
powershell -NoProfile -Command "$pkg='%PKG%'; $out=Join-Path $pkg 'SHA256.txt'; Get-ChildItem $pkg -File | Where-Object { $_.Name -ne 'SHA256.txt' } | ForEach-Object { $h=(Get-FileHash $_.FullName -Algorithm SHA256).Hash; '{0}  {1}  {2}' -f $h, $_.Length, $_.Name } | Set-Content -Encoding ASCII $out"

if "!RAWR!"=="" (
  echo FIRST_FAILURE_CLASS=CLI_RAWR_ABSENT> "%EVID%\RECEIPT.txt"
  echo NOTE=Ext rebuilt; rawr missing for live CU GUI prove>> "%EVID%\RECEIPT.txt"
  exit /b 3
)

"%PKG%\rawr.exe" tools list > "%EVID%\cli_tools_list.txt" 2>&1
findstr /i "computer_use.screenshot" "%EVID%\cli_tools_list.txt" >nul
if errorlevel 1 (
  echo FIRST_FAILURE_CLASS=CLI_CU_TOOLS_ABSENT> "%EVID%\RECEIPT.txt"
  echo NOTE=rawr present but computer_use.* not listed>> "%EVID%\RECEIPT.txt"
  type "%EVID%\cli_tools_list.txt" >> "%EVID%\RECEIPT.txt"
  exit /b 4
)

taskkill /IM notepad.exe /F >nul 2>&1
start "" notepad.exe
timeout /t 2 /nobreak >nul
for /f "tokens=2 delims=," %%A in ('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH') do set NPID=%%~A
set NPID=!NPID:"=!
set RAWRXD_PARENT_PID=!NPID!
set RAWRXD_CU_ALLOW_PIDS=!NPID!
echo NPID=!NPID!>> "%LOG%"

"%PKG%\rawr.exe" tools run computer_use.find_window title=Notepad > "%EVID%\find_out.txt" 2>&1
set HWND=
for /f "tokens=2 delims== " %%H in ('findstr /i "hwnd=" "%EVID%\find_out.txt"') do set HWND=%%H
if "!HWND!"=="" (
  echo FIRST_FAILURE_CLASS=CU_GUI_FIND_WINDOW_FAIL> "%EVID%\RECEIPT.txt"
  type "%EVID%\find_out.txt" >> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 5
)

"%PKG%\rawr.exe" tools run computer_use.screenshot hwnd=!HWND! > "%EVID%\shot_out.txt" 2>&1
set SHOT=
for /f "tokens=2 delims== " %%S in ('findstr /i "screenshot=" "%EVID%\shot_out.txt"') do set SHOT=%%S
if "!SHOT!"=="" (
  echo FIRST_FAILURE_CLASS=CU_GUI_SCREENSHOT_OWN_WINDOW_FAIL> "%EVID%\RECEIPT.txt"
  type "%EVID%\shot_out.txt" >> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 6
)
if not exist "!SHOT!" (
  echo FIRST_FAILURE_CLASS=CU_GUI_BMP_MISSING> "%EVID%\RECEIPT.txt"
  echo screenshot_path=!SHOT!>> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 7
)

copy /Y "!SHOT!" "%EVID%\capture.bmp" >nul
taskkill /IM notepad.exe /F >nul 2>&1

echo CU_GUI_E2E=PASS> "%EVID%\RECEIPT.txt"
echo NOTE=CLI tools run with RAWRXD_PARENT_PID allowlist + BMP evidence>> "%EVID%\RECEIPT.txt"
echo NOTE2=Orphan verify alone is NOT credited as CU_GUI_E2E>> "%EVID%\RECEIPT.txt"
echo PACKAGE=%PKG%>> "%EVID%\RECEIPT.txt"
echo HWND=!HWND!>> "%EVID%\RECEIPT.txt"
echo SCREENSHOT=!SHOT!>> "%EVID%\RECEIPT.txt"
echo BMP=%EVID%\capture.bmp>> "%EVID%\RECEIPT.txt"
echo PROMOTE=0>> "%EVID%\RECEIPT.txt"
type "%EVID%\EXT_SHA.txt" >> "%EVID%\RECEIPT.txt"
echo WAVE1_REBUILD_DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
