@echo off
setlocal EnableExtensions
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005
set CAND=%LANE%\candidates\tip_final_005
set LOG=%LANE%\artifacts\force_rebuild_tip005.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set EXE_OUT=%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe

echo ===== FORCE START %DATE% %TIME% > "%LOG%"
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >> "%LOG%" 2>&1
taskkill /F /IM powershell.exe /FI "WINDOWTITLE eq *ea5d*" >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul

echo BEFORE_HASH>> "%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 >> "%LOG%" 2>&1
certutil -hashfile "%EXE_OUT%" SHA256 >> "%LOG%" 2>&1

echo DEL_OBJ>> "%LOG%"
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_Commands.cpp.obj" >> "%LOG%" 2>&1
del /F /Q "%EXE_OUT%" >> "%LOG%" 2>&1

call "%VCVARS%" >> "%LOG%" 2>&1
echo PATH_HAS_NINJA>> "%LOG%"
where ninja >> "%LOG%" 2>&1
cd /d "%BUILD%"
echo CWD=%CD%>> "%LOG%"
echo NINJA_BEGIN>> "%LOG%"
ninja -v RawrXD-Win32IDE-Native-Ext >> "%LOG%" 2>&1
set NR=%ERRORLEVEL%
echo NINJA_EXIT=%NR%>> "%LOG%"
if not exist "%EXE_OUT%" (
  echo EXE_MISSING_AFTER_NINJA>> "%LOG%"
  exit /b 2
)

echo AFTER_BUILD_HASH>> "%LOG%"
certutil -hashfile "%EXE_OUT%" SHA256 >> "%LOG%" 2>&1
findstr /C:RAWRXD_PROBLEMS_FIXTURE "%EXE_OUT%" >nul
if errorlevel 1 (echo PROBLEMS_FIXTURE_STR=0>> "%LOG%") else (echo PROBLEMS_FIXTURE_STR=1>> "%LOG%")
findstr /C:PROBLEMS_FIXTURE_LAUNCH "%EXE_OUT%" >nul
if errorlevel 1 (echo LAUNCH_STR=0>> "%LOG%") else (echo LAUNCH_STR=1>> "%LOG%")

mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%EXE_OUT%" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
copy /Y "%EXE_OUT%" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_final_005_sha.txt"
type "%LANE%\artifacts\tip_final_005_sha.txt" >> "%LOG%"

echo HARNESS_BEGIN>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_final_005_hwnd2" -WaitSec 70 > "%LANE%\artifacts\tip005_hwnd2_console.txt" 2>&1
echo HARNESS_EXIT=%ERRORLEVEL%>> "%LOG%"
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP005_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
type "%LANE%\artifacts\TIP005_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >> "%LOG%"
echo ===== FORCE DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
