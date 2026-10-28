@echo off
setlocal
cd /d "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
set OUT=G:\~dev\rawrxd\evidence\CAMPAIGN_PHASE_9_PERFORMANCE_001
echo START_UTC=%DATE% %TIME%> "%OUT%\logs\run_meta.txt"
echo EXPECTED_EXE_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145>> "%OUT%\logs\run_meta.txt"
echo MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf>> "%OUT%\logs\run_meta.txt"
echo MAX_TOKENS_CLI=16>> "%OUT%\logs\run_meta.txt"
echo NOTE=MEASURED_EXTEND_ONLY_NO_PERF_PASS>> "%OUT%\logs\run_meta.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Count from one to five in words." --max-tokens 16 --backend local --verbose > "%OUT%\logs\tps16_stdout.log" 2> "%OUT%\logs\tps16_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "%OUT%\logs\run_meta.txt"
echo END_UTC=%DATE% %TIME%>> "%OUT%\logs\run_meta.txt"
echo DONE
endlocal
