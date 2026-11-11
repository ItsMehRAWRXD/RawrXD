@echo off
REM P0 CU GUI E2E — build parent-PID fix + prove (not orphan-verify credit)
setlocal EnableExtensions
set EVID=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\cu_gui_e2e_003
set BT=F:\rawrxd\build_tip_debug_rel
set PKG=F:\rawrxd\release\RawrXD-readiness-rc5e
mkdir "%EVID%" 2>nul
mkdir "%PKG%" 2>nul

echo UTC=%DATE% %TIME%> "%EVID%\BUILD_START.txt"
echo PROMOTE=0>> "%EVID%\BUILD_START.txt"

cmake --build "%BT%" --config Release --target rawrxd_computer_use --target RawrXD-CLI-V2 --target rawrxd_computer_use_ide_verify --target RawrXD-Win32IDE-Native-Ext -j 4 > "%EVID%\build.log" 2>&1
if errorlevel 1 (
  echo FIRST_FAILURE_CLASS=BUILD_FAIL> "%EVID%\RECEIPT.txt"
  echo See build.log>> "%EVID%\RECEIPT.txt"
  exit /b 1
)

REM Prefer known output locations
set EXT=
for %%P in (
  "%BT%\src\win32app\Release\RawrXD-Win32IDE-Native-Ext.exe"
  "%BT%\Release\RawrXD-Win32IDE-Native-Ext.exe"
  "%BT%\bin-msvc\RawrXD-Win32IDE-Native-Ext.exe"
) do if exist %%~P set EXT=%%~P
set RAWR=
for %%P in (
  "%BT%\bin-msvc\rawr.exe"
  "%BT%\Release\rawr.exe"
  "%BT%\src\Release\rawr.exe"
) do if exist %%~P set RAWR=%%~P
set VERIFY=
for %%P in (
  "%BT%\src\computer_use\Release\rawrxd_computer_use_ide_verify.exe"
  "%BT%\src\computer_use\rawrxd_computer_use_ide_verify.exe"
  "%BT%\Release\rawrxd_computer_use_ide_verify.exe"
) do if exist %%~P set VERIFY=%%~P

if "%EXT%"=="" (
  echo FIRST_FAILURE_CLASS=EXT_BINARY_ABSENT> "%EVID%\RECEIPT.txt"
  exit /b 2
)
if "%RAWR%"=="" (
  echo FIRST_FAILURE_CLASS=CLI_RAWR_ABSENT> "%EVID%\RECEIPT.txt"
  exit /b 3
)

copy /Y "%EXT%" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "%RAWR%" "%PKG%\rawr.exe" >nul
if not "%VERIFY%"=="" copy /Y "%VERIFY%" "%PKG%\rawrxd_computer_use_ide_verify.exe" >nul

certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%EVID%\EXT_SHA.txt"
certutil -hashfile "%PKG%\rawr.exe" SHA256 > "%EVID%\RAWR_SHA.txt"

REM CLI CU tools present?
"%PKG%\rawr.exe" tools list > "%EVID%\cli_tools_list.txt" 2>&1
findstr /i "computer_use.screenshot" "%EVID%\cli_tools_list.txt" >nul
if errorlevel 1 (
  echo FIRST_FAILURE_CLASS=CLI_CU_TOOLS_ABSENT> "%EVID%\RECEIPT.txt"
  echo NOTE=rawr rebuilt but computer_use.* not listed>> "%EVID%\RECEIPT.txt"
  exit /b 4
)

REM Live CLI agent-path HWND ownership: allow parent = this cmd's PID owning a window via notepad helper
start "" notepad.exe
timeout /t 2 /nobreak >nul
for /f "tokens=2 delims=," %%A in ('tasklist /FI "IMAGENAME eq notepad.exe" /FO CSV /NH') do set NPID=%%~A
set RAWRXD_PARENT_PID=%NPID%
set RAWRXD_CU_ALLOW_PIDS=%NPID%

"%PKG%\rawr.exe" tools run computer_use.find_window title=Notepad > "%EVID%\find_out.txt" 2>&1
findstr /i "hwnd=" "%EVID%\find_out.txt" > "%EVID%\hwnd_line.txt"
set HWND=
for /f "tokens=2 delims== " %%H in ('findstr /i "hwnd=" "%EVID%\find_out.txt"') do set HWND=%%H
if "%HWND%"=="" (
  echo FIRST_FAILURE_CLASS=CU_GUI_FIND_WINDOW_FAIL> "%EVID%\RECEIPT.txt"
  type "%EVID%\find_out.txt" >> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 5
)

"%PKG%\rawr.exe" tools run computer_use.screenshot hwnd=%HWND% > "%EVID%\shot_out.txt" 2>&1
findstr /i "screenshot=" "%EVID%\shot_out.txt" > "%EVID%\shot_path_line.txt"
set SHOT=
for /f "tokens=2 delims== " %%S in ('findstr /i "screenshot=" "%EVID%\shot_out.txt"') do set SHOT=%%S
if "%SHOT%"=="" (
  echo FIRST_FAILURE_CLASS=CU_GUI_SCREENSHOT_OWN_WINDOW_FAIL> "%EVID%\RECEIPT.txt"
  type "%EVID%\shot_out.txt" >> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 6
)
if not exist "%SHOT%" (
  echo FIRST_FAILURE_CLASS=CU_GUI_BMP_MISSING> "%EVID%\RECEIPT.txt"
  echo screenshot_path=%SHOT%>> "%EVID%\RECEIPT.txt"
  taskkill /IM notepad.exe /F >nul 2>&1
  exit /b 7
)

copy /Y "%SHOT%" "%EVID%\capture.bmp" >nul
taskkill /IM notepad.exe /F >nul 2>&1

echo CU_GUI_E2E=PASS> "%EVID%\RECEIPT.txt"
echo NOTE=CLI tools run with RAWRXD_PARENT_PID allowlist + BMP evidence>> "%EVID%\RECEIPT.txt"
echo NOTE2=Orphan verify alone is NOT credited as CU_GUI_E2E>> "%EVID%\RECEIPT.txt"
echo PACKAGE=%PKG%>> "%EVID%\RECEIPT.txt"
echo HWND=%HWND%>> "%EVID%\RECEIPT.txt"
echo SCREENSHOT=%SHOT%>> "%EVID%\RECEIPT.txt"
echo BMP=%EVID%\capture.bmp>> "%EVID%\RECEIPT.txt"
echo PROMOTE=0>> "%EVID%\RECEIPT.txt"
type "%EVID%\EXT_SHA.txt" >> "%EVID%\RECEIPT.txt"
exit /b 0
