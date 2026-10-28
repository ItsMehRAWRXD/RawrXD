@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo MAX_TOKENS_CLI=16>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo PROVENANCE=TIP_ABSORB_RELINK_001>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo FAMILY=gemma3_ne_tinyllama>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_003\run_meta_partial.txt"
echo DONE
endlocal
