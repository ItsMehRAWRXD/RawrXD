@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
dumpbin /headers "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe" | findstr /i pdb
exit /b %errorlevel%
