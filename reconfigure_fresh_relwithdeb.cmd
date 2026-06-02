@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 (
  echo VSDEVCMD_FAILED
  exit /b 1
)
if exist d:\rawrxd\build_win32ide\CMakeCache.txt del /f /q d:\rawrxd\build_win32ide\CMakeCache.txt
if exist d:\rawrxd\build_win32ide\CMakeFiles rmdir /s /q d:\rawrxd\build_win32ide\CMakeFiles
cmake -S d:\rawrxd -B d:\rawrxd\build_win32ide -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
if errorlevel 1 (
  echo CMAKE_CONFIGURE_FAILED
  exit /b 1
)
cmake --build d:\rawrxd\build_win32ide --target RawrXD-VulkanValidationTax
exit /b %errorlevel%
