@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 (
  echo VSDEVCMD_FAILED
  exit /b 1
)
set "SDK_BIN=C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64"
set "SDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WINDOWS_SDK_UM_LIB=%SDK_ROOT%\Lib\10.0.22621.0\um\x64"
set "WindowsSdkDir=%SDK_ROOT%\"
set "WindowsSDKLibVersion=10.0.22621.0\"
set "LIB=%LIB%;%WINDOWS_SDK_UM_LIB%"
if exist d:\rawrxd\build_win32ide\CMakeCache.txt del /f /q d:\rawrxd\build_win32ide\CMakeCache.txt
if exist d:\rawrxd\build_win32ide\CMakeFiles rmdir /s /q d:\rawrxd\build_win32ide\CMakeFiles
cmake -S d:\rawrxd -B d:\rawrxd\build_win32ide -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_RC_COMPILER="%SDK_BIN%/rc.exe" -DCMAKE_MT="%SDK_BIN%/mt.exe"
if errorlevel 1 (
  echo CMAKE_CONFIGURE_FAILED
  exit /b 1
)
cmake --build d:\rawrxd\build_win32ide --target RawrXD-VulkanValidationTax
exit /b %errorlevel%
