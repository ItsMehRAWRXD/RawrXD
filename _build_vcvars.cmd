@echo off
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cmake --build d:\rawrxd\build_win32ide --config RelWithDebInfo --target RawrXD-VulkanValidationTax
