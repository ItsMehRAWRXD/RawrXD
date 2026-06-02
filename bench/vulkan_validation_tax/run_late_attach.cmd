@echo off
setlocal
set PID=%~1
if "%PID%"=="" (
  echo Usage: %~nx0 PID
  exit /b 2
)
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -p %PID% -logo "D:\rawrxd\bench\vulkan_validation_tax\cdb_late_attach_final.log" -c "sxe av; sxe ch; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; kb 80; r; u @rip-24 @rip+24; !gle; q"
exit /b %ERRORLEVEL%
