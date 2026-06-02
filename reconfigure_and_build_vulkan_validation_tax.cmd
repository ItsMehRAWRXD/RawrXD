@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 (
  echo VSDEVCMD_FAILED
  exit /b 1
)
set "CL_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
cmake -S d:\rawrxd -B d:\rawrxd\build_win32ide -G Ninja -DCMAKE_C_COMPILER="%CL_PATH%" -DCMAKE_CXX_COMPILER="%CL_PATH%" -DCMAKE_BUILD_TYPE=RelWithDebInfo
if errorlevel 1 (
  echo CMAKE_CONFIGURE_FAILED
  exit /b 1
)
cmake --build d:\rawrxd\build_win32ide --target RawrXD-VulkanValidationTax
exit /b %errorlevel%
