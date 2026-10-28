@echo off
echo RECOVERY_KILL %DATE% %TIME%>> "G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_authoritative.log"
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
taskkill /F /IM glslc.exe >nul 2>&1
taskkill /F /IM deep2_bench_tps.exe >nul 2>&1
echo RECOVERY_KILL_DONE %DATE% %TIME%>> "G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_authoritative.log"
echo KILL_OK
exit /b 0
