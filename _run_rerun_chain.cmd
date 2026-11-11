@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - full evidence re-run after RAWRXD_STREAM_CANCEL_001
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set BIN=F:\rawrxd\tmp_build_e2e

echo RERUN_START >> %EV%\chain_status.txt

REM 1. numerics preservation: single-pass capture must match pre-change bit-for-bit
F:\rawrxd\tmp_build_cap\capture_native_logits.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf %EV%\native_tf_post_stream "1 185 16 15 15 15 15 15 15 15 12 384 2 16 24 207 71955 1392 13 1002 6 95 3882 124 2 16 146 24 151 384 37 1827 253 16 24 92 1024 1827 253 16 24 92 12 22 738 30840 4399 4633 15 23 0 626 726 1628 2285 966 6 4 0 82 10 113 4647 1075 2" --single > %EV%\capture_post_stream_run.log 2>&1
echo CAPTURE_RC=%errorlevel% >> %EV%\chain_status.txt

REM 2. DLL lifecycle + generation evidence
F:\rawrxd\build_cert\bin\Release\RawrXDCore_Test.exe > %EV%\dll_test_run.log 2>&1
echo DLLTEST_RC=%errorlevel% >> %EV%\chain_status.txt

REM 3. per-step authority evidence
%BIN%\e2e_evidence.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf %EV% --tokens 1 185 16 > %EV%\e2e_evidence_run.log 2>&1
echo E2E_RC=%errorlevel% >> %EV%\chain_status.txt

REM 4. endurance / streaming / cancellation / reuse through the production DLL
%BIN%\e2e_endurance.exe --len 512 > %EV%\endurance_512.log 2>&1
echo ENDURANCE_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --stream 64 > %EV%\streaming_64.log 2>&1
echo STREAM_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --cancel 40 > %EV%\cancellation.log 2>&1
echo CANCEL_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --reuse 8 > %EV%\context_reuse6.log 2>&1
echo REUSE_RC=%errorlevel% >> %EV%\chain_status.txt
echo RERUN_COMPLETE >> %EV%\chain_status.txt
exit /b 0
