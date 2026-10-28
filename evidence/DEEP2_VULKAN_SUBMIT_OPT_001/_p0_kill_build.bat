@echo off
echo KILL_START %DATE% %TIME%> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log
taskkill /F /IM ninja.exe >> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log 2>&1
taskkill /F /IM cl.exe >> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log 2>&1
taskkill /F /IM link.exe >> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log 2>&1
taskkill /F /IM glslc.exe >> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log 2>&1
taskkill /F /IM deep2_bench_tps.exe >> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log 2>&1
echo KILL_DONE %DATE% %TIME%>> G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\p0_kill.log
