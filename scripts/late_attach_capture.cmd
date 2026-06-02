@echo off
setlocal enableextensions

set TARGET=D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe
set LOG=D:\rawrxd\bench\vulkan_validation_tax\cdb_late_attach_final.log
set CDB=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe

echo [1/5] Killing OBS processes...
taskkill /F /IM obs64.exe >nul 2>&1
taskkill /F /IM obs.exe >nul 2>&1
echo [2/5] Verifying OBS is not running...
tasklist | findstr /I obs

echo [3/5] Killing stale benchmark processes...
taskkill /F /IM RawrXD-VulkanValidationTax.exe >nul 2>&1

echo [4/5] Launching guards-off benchmark detached...
start "" "%TARGET%" --iterations 50000 --mode=guards-off

echo [5/5] Waiting 10s, then attaching cdb...
timeout /t 10 /nobreak >nul

del "%LOG%" >nul 2>&1
for /f "tokens=2" %%a in ('tasklist ^| findstr /I "RawrXD-VulkanValidationTax.exe"') do (
  "%CDB%" -p %%a -logo "%LOG%" -c "sxe av; sxe ch; sxe clr; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; kb 80; r; u @rip-24 @rip+24; !gle; q"
)

echo Done. Log: %LOG%
endlocal
