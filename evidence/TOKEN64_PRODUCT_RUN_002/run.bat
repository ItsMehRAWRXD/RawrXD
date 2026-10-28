@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
echo MAX_TOKENS_CLI=64>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Write a short paragraph about why clear writing matters. Keep going until you have enough text." --max-tokens 64 --backend local --verbose > "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\TOKEN64_PRODUCT_RUN_002\run_meta_partial.txt"
echo DONE
endlocal
