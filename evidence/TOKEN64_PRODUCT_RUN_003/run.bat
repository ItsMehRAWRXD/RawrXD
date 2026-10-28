@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo MAX_TOKENS_CLI=64>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo PROVENANCE=CAMELLIA_HMAC_PRODUCT_ABSORB_001>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." --max-tokens 64 --backend local --verbose > "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_003\run_meta_partial.txt"
echo DONE
endlocal
