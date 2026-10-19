@echo off
set RAWRXD_HOST_DECODE=1
set DEEP2_DUALSTICK_ARM=0
set RAWRXD_NO_VULKAN=1
set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json
"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_bin\RawrXD-Win32IDE_r1cap.exe" --headless --local --port 11438 --dir "G:\~dev\rawrxd" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_r1cap\out.txt" 2> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_r1cap\err.txt"
