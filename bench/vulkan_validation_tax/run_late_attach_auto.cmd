@echo off
setlocal ENABLEDELAYEDEXPANSION
set TARGET=RawrXD-VulkanValidationTax.exe
set EXE=D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe
set ARGS=--iterations 50000 --mode=guards-off
set LOG=D:\rawrxd\bench\vulkan_validation_tax\cdb_late_attach_final.log

start "" /b "%EXE%" %ARGS%
set PID=
for /L %%I in (1,1,30) do (
  for /f "tokens=2 delims=," %%P in ('tasklist /FI "IMAGENAME eq %TARGET%" /FO CSV /NH ^| findstr /I "%TARGET%"') do (
    set PID=%%~P
    goto :attach
  )
  ping -n 2 127.0.0.1 >nul
)
echo FAILED_TO_FIND_PID
exit /b 3

:attach
if "%PID%"=="" (
  echo EMPTY_PID
  exit /b 4
)
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -p %PID% -logo "%LOG%" -c "sxe av; sxe ch; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; kb 80; r; u @rip-24 @rip+24; !gle; q"
exit /b %ERRORLEVEL%
