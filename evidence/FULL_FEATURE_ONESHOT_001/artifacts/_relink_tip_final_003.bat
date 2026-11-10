@echo off
setlocal EnableExtensions
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set BDIR=F:\rawrxd\build_tip_chat_ctrl_enter_002
set STAGE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_003
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_003
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

echo start> "%OUT%\relink003.txt"
call "%VCVARS%" > "%OUT%\relink003_vc.txt" 2>&1
if errorlevel 1 (
  echo vcfail> "%OUT%\relink003.txt"
  exit /b 91
)
cd /d "%BDIR%" || exit /b 93
echo building>> "%OUT%\relink003.txt"
ninja CMakeFiles/RawrXD-Win32IDE-Native-Ext.dir/src/win32app/Win32NativeDebugBackend.cpp.obj > "%OUT%\relink003_obj.txt" 2>&1
echo obj_rc=%ERRORLEVEL%>> "%OUT%\relink003.txt"
ninja RawrXD-Win32IDE-Native-Ext > "%OUT%\relink003_ninja.txt" 2>&1
set RC=%ERRORLEVEL%
echo ninja_rc=%RC%>> "%OUT%\relink003.txt"
if not "%RC%"=="0" exit /b %RC%
if not exist "bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo missing>> "%OUT%\relink003.txt"
  exit /b 94
)
mkdir "%STAGE%" 2>nul
mkdir "%PKG%" 2>nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%STAGE%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%STAGE%\RawrXD-Win32IDE-Native.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native.exe" >nul
certutil -hashfile "bin\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%PKG%\SHA256.txt"
copy /Y "%PKG%\SHA256.txt" "%STAGE%\SHA256.txt" >nul
echo OK>> "%OUT%\relink003.txt"
type "%PKG%\SHA256.txt" >> "%OUT%\relink003.txt"
exit /b 0
