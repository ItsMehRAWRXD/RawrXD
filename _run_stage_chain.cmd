@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - stage differential capture (positions 1 and 2)
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set TOKENS=1 185 16 15 15 15 15 15 15 15 12 384 2 16 24 207 71955 1392 13 1002 6 95 3882 124 2 16 146 24 151 384 37 1827 253 16 24 92 1024 1827 253 16 24 92 12 22 738 30840 4399 4633 15 23 0 626 726 1628 2285 966 6 4 0 82 10 113 4647 1075 2

F:\rawrxd\tmp_build_cert_exec\rawrxd_modelgenie_ir_executor.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf %EV% --teacher-forced %TOKENS% --differential %EV%\diff_pos1f --diff-position 1 > %EV%\diff_pos1f_run.log 2>&1
echo POS1_RC=%errorlevel% >> %EV%\chain_status.txt
F:\rawrxd\tmp_build_cert_exec\rawrxd_modelgenie_ir_executor.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf %EV% --teacher-forced %TOKENS% --differential %EV%\diff_pos2e --diff-position 2 > %EV%\diff_pos2e_run.log 2>&1
echo POS2_RC=%errorlevel% >> %EV%\chain_status.txt
echo STAGE_CHAIN_COMPLETE >> %EV%\chain_status.txt
exit /b 0
