@echo off
setlocal EnableExtensions
rem Real vcvars+ninja rebuild into tip_chat_dispatch_001. Never touch A4F / tip_final_004 / tip_final_005.
set LOG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\TIP_CHAT_DISPATCH_001_BUILD_cmd.log
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001
set BUILD=F:\rawrxd\build_tip_chat_ctrl_enter_002
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set NINJA=C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Links\ninja.exe
if not exist "%NINJA%" set NINJA=C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe
if not exist "%NINJA%" set NINJA=C:\Program Files\CMake\bin\ninja.exe
if not exist "%NINJA%" set NINJA=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ninja.exe

echo START %DATE% %TIME%>"%LOG%"
echo NINJA_PATH=%NINJA%>>"%LOG%"
if not exist "%VCVARS%" (
  echo VCVARS_MISS>>"%LOG%"
  exit /b 2
)
if not exist "%NINJA%" (
  echo NINJA_MISS>>"%LOG%"
  exit /b 3
)
if not exist "%BUILD%\build.ninja" (
  echo BUILD_DIR_MISS>>"%LOG%"
  exit /b 4
)

echo BEFORE_VCVARS>>"%LOG%"
call "%VCVARS%"
if errorlevel 1 (
  echo VCVARS_FAIL errorlevel=%ERRORLEVEL%>>"%LOG%"
  rem vcvars often leaves nonzero; continue if cl is on PATH
)
where cl >>"%LOG%" 2>&1
where cl >nul 2>&1
if errorlevel 1 (
  echo CL_NOT_ON_PATH>>"%LOG%"
  exit /b 5
)
echo AFTER_VCVARS>>"%LOG%"

cd /d "%BUILD%"
if errorlevel 1 (
  echo CD_FAIL>>"%LOG%"
  exit /b 6
)
echo BEFORE_NINJA>>"%LOG%"
"%NINJA%" RawrXD-Win32IDE-Native-Ext
set NR=%ERRORLEVEL%
echo NINJA_RC=%NR%>>"%LOG%"
if not "%NR%"=="0" (
  echo NINJA_FAIL>>"%LOG%"
  exit /b 7
)
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo EXE_MISS>>"%LOG%"
  exit /b 1
)

mkdir "%PKG%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe">>"%LOG%" 2>&1
if not exist "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" (
  echo COPY_FAIL>>"%LOG%"
  exit /b 8
)

for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 ^| findstr /R /V ":"') do (
  >"%PKG%\SHA256.txt" echo %%H
  echo TIP_SHA256=%%H>>"%LOG%"
  goto :hashed
)
:hashed
findstr /C:"CHAT_SEND_ARMED" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (
  echo INSTRUMENT_STRINGS=ABSENT>>"%LOG%"
) else (
  echo INSTRUMENT_STRINGS=PRESENT>>"%LOG%"
)
echo A4F_UNTOUCHED=1>>"%LOG%"
echo TIP_FINAL_004_UNTOUCHED=1>>"%LOG%"
echo TIP_FINAL_005_UNTOUCHED=1>>"%LOG%"
echo PROMOTE=0>>"%LOG%"
echo DONE %DATE% %TIME%>>"%LOG%"
exit /b 0
