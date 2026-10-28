@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\run_meta_partial.txt"
echo MODEL=G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\run_meta_partial.txt"
echo FAMILY=gemma3_ne_tinyllama>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\MULTI_FAMILY_PRODUCT_001\run_meta_partial.txt"
echo DONE
endlocal
