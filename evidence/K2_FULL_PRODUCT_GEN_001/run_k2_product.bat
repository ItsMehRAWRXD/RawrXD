@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\logs" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
set RAWRXD_DEEP2_ALLOW_ELASTIC=1
set K2_MODEL=F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo MODEL=%K2_MODEL%>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo MAX_TOKENS_CLI=64>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo EXPECTED_EXE_SHA=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo FAMILY=kimi_k2_instruct_0905>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo ELASTIC=RAWRXD_DEEP2_ALLOW_ELASTIC >> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model "%K2_MODEL%" --prompt "Say hi in one word." --max-tokens 64 --backend local --verbose > "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\logs\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\logs\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\K2_FULL_PRODUCT_GEN_001\run_meta_partial.txt"
echo DONE
endlocal
