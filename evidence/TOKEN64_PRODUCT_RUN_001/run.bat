@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
echo MAX_TOKENS_CLI=64>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." --max-tokens 64 --backend local --verbose > "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_001\run_meta_partial.txt"
echo DONE
endlocal
