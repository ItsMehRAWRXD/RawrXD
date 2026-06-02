@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
echo LIB=%LIB%
echo UniversalCRTSdkDir=%UniversalCRTSdkDir%
echo UCRTVersion=%UCRTVersion%
echo WindowsSdkDir=%WindowsSdkDir%
echo WindowsSDKLibVersion=%WindowsSDKLibVersion%
if exist "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" (echo KERNEL32_LIB_EXISTS) else (echo KERNEL32_LIB_MISSING)
