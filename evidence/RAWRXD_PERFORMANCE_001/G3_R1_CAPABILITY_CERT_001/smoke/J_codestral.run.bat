@echo off
set RAWRXD_HOST_DECODE=1
set RAWRXD_FORCE_CPU_INFERENCE=1
set DEEP2_MINIMAL_ENHANCE=1
set DEEP2_DUALSTICK_ARM=0
set RAWRXD_NO_VULKAN=1
set DEEP2_MARS=0
set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json
"C:\r1cert\smoke_bin\RawrXD-Win32IDE_r1cap_run.exe" --headless --local --port 11435 --dir "G:\~dev\rawrxd" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke\J_codestral.out.txt" 2> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke\J_codestral.err.txt"
