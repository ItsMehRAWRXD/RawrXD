@echo off
setlocal EnableExtensions
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set BDIR=F:\rawrxd\build_tip_chat_ctrl_enter_002
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_004
set STAGE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_004
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
echo core_rebuild> "%OUT%\tf4_core.txt"
call "%VCVARS%" > "%OUT%\tf4_core_vc.txt" 2>&1
cd /d "%BDIR%" || exit /b 93
del /F /Q "CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_Core.cpp.obj" 2>nul
echo building_core>> "%OUT%\tf4_core.txt"
ninja CMakeFiles/RawrXD-Win32IDE-Native-Ext.dir/src/win32app/Win32IDE_Core.cpp.obj > "%OUT%\tf4_core_obj.txt" 2>&1
echo obj_rc=%ERRORLEVEL%>> "%OUT%\tf4_core.txt"
ninja RawrXD-Win32IDE-Native-Ext > "%OUT%\tf4_core_link.txt" 2>&1
set RC=%ERRORLEVEL%
echo link_rc=%RC%>> "%OUT%\tf4_core.txt"
if not "%RC%"=="0" exit /b %RC%
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%STAGE%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%STAGE%\RawrXD-Win32IDE-Native.exe" >nul
certutil -hashfile "bin\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%PKG%\SHA256.txt"
copy /Y "%PKG%\SHA256.txt" "%STAGE%\SHA256.txt" >nul
echo OK>> "%OUT%\tf4_core.txt"
type "%PKG%\SHA256.txt" >> "%OUT%\tf4_core.txt"
exit /b 0
