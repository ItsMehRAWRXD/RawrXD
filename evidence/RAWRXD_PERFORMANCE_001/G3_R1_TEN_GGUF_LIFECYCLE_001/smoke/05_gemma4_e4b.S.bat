@echo off
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set DEEP2_DUALSTICK_ARM=0
set RAWRXD_NO_VULKAN=1
set DEEP2_MARS=0
set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json
"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r01_laa.exe" --headless --local --port 11435 --dir G:\~dev\rawrxd > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke\05_gemma4_e4b.S.out.txt" 2> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke\05_gemma4_e4b.S.err.txt"
