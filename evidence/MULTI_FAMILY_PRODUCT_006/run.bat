@echo off
setlocal
cd /d "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo MAX_TOKENS_CLI=16>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo PROVENANCE=TIP_FREEZE_001>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo FAMILY=gemma3_ne_tinyllama>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"

RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_006\run_meta_partial.txt"
echo DONE
endlocal
