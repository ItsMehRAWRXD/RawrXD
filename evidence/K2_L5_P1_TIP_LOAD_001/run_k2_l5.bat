@echo off
setlocal
cd /d "G:\~dev\rawrxd\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
set RAWRXD_DEEP2_ALLOW_ELASTIC=1
set K2_MODEL=F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo MODEL=%K2_MODEL%>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo EXE_SHA=6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo MAX_TOKENS_CLI=8>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo FAMILY=kimi_k2_instruct_0905>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo QUANT=Q4_K_M>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo LANE=L5_P1>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model "%K2_MODEL%" --prompt "Say hi in one word." --max-tokens 8 --backend local --verbose > "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\logs\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\logs\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\K2_L5_P1_TIP_LOAD_001\run_meta_partial.txt"
echo DONE
endlocal
