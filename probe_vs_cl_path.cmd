@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 (
  echo VSDEVCMD_FAILED
  exit /b 1
)
where cl
cl /Bv
exit /b %errorlevel%
