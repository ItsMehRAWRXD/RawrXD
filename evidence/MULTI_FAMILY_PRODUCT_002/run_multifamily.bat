@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo FAMILY=gemma3_ne_tinyllama>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo MAX_TOKENS_CLI=16>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo PROVENANCE=CAMELLIA_HMAC_PRODUCT_ABSORB_001>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_002\run_meta_partial.txt"
echo DONE
endlocal
