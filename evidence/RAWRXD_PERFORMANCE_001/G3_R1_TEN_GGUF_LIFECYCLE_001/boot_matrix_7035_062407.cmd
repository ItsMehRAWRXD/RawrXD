@echo off
cd /d "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001"
echo BOOT_START=%DATE% %TIME% > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\matrix_boot_062407.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\run_r1_matrix_KEEPENV7035.ps1" > "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\matrix_stdout_7035_062407.txt" 2> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\matrix_stderr_7035_062407.txt"
echo MATRIX_WRAP_EXIT=%ERRORLEVEL% >> "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\matrix_boot_062407.txt"
