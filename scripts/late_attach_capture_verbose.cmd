@echo off
setlocal enableextensions enabledelayedexpansion

set TARGET=D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe
set LOG=D:\rawrxd\bench\vulkan_validation_tax\cdb_late_attach_final.log
set STATUS=D:\rawrxd\bench\vulkan_validation_tax\late_attach_status.log
set STDOUT_LOG=D:\rawrxd\bench\vulkan_validation_tax\late_attach_target_stdout.txt
set STDERR_LOG=D:\rawrxd\bench\vulkan_validation_tax\late_attach_target_stderr.txt
set CDB=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe

del "%STATUS%" >nul 2>&1
del "%LOG%" >nul 2>&1
del "%STDOUT_LOG%" >nul 2>&1
del "%STDERR_LOG%" >nul 2>&1

echo [INFO] start %date% %time%>>"%STATUS%"
echo [INFO] TARGET=%TARGET%>>"%STATUS%"
echo [INFO] CDB=%CDB%>>"%STATUS%"

taskkill /F /IM obs64.exe >nul 2>&1
taskkill /F /IM obs.exe >nul 2>&1
echo [INFO] OBS after kill:>>"%STATUS%"
tasklist | findstr /I obs >>"%STATUS%" 2>&1

taskkill /F /IM RawrXD-VulkanValidationTax.exe >nul 2>&1
echo [INFO] launching target...>>"%STATUS%"
start "" /b "%TARGET%" --mode guards-off --iterations 50000 --warmup 200 --json

set ATTACHED=0
set FOUND_PID=
for /l %%S in (1,1,30) do (
  for /f "tokens=2" %%a in ('tasklist ^| findstr /I "RawrXD-VulkanValidationTax.exe"') do (
    if "!FOUND_PID!"=="" set FOUND_PID=%%a
  )
  if not "!FOUND_PID!"=="" goto :attach_now
  timeout /t 1 /nobreak >nul
)

echo [INFO] PID scan after retries:>>"%STATUS%"
tasklist | findstr /I "RawrXD-VulkanValidationTax.exe" >>"%STATUS%" 2>&1
goto :after_attach

:attach_now
echo [INFO] attaching to PID !FOUND_PID!>>"%STATUS%"
"%CDB%" -p !FOUND_PID! -logo "%LOG%" -c "sxe av; sxe ch; sxe clr; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; k; r; u rip; q" >>"%STATUS%" 2>&1
echo [INFO] cdb exit code !errorlevel! for PID !FOUND_PID!>>"%STATUS%"
set ATTACHED=1

:after_attach

if "%ATTACHED%"=="0" echo [WARN] no PID found for attach>>"%STATUS%"
if exist "%LOG%" (
  for %%I in ("%LOG%") do echo [INFO] log bytes %%~zI>>"%STATUS%"
) else (
  echo [WARN] cdb log not created>>"%STATUS%"
)

if exist "%STDOUT_LOG%" for %%I in ("%STDOUT_LOG%") do echo [INFO] target stdout bytes %%~zI>>"%STATUS%"
if exist "%STDERR_LOG%" for %%I in ("%STDERR_LOG%") do echo [INFO] target stderr bytes %%~zI>>"%STATUS%"

echo [INFO] end %date% %time%>>"%STATUS%"
endlocal
