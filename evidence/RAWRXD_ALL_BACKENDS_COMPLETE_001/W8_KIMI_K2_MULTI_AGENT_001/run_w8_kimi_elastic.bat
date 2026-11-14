@echo off
setlocal
cd /d G:\~dev\rawrxd\build_win32ide_link001\bin
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
set RAWRXD_DEEP2_ALLOW_ELASTIC=1
set DEEP2_DUALSTICK_ARM=0
set CAPACITY_PROOF_REOPEN=0
set K3_RUNTIME_ADOPTION=0
echo START_LOCAL=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W8_KIMI_K2_MULTI_AGENT_001\run_meta_elastic.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf" --prompt "Say hi in one word." --max-tokens 8 --backend local --verbose > "G:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W8_KIMI_K2_MULTI_AGENT_001\logs\elastic_stdout.log" 2> "G:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W8_KIMI_K2_MULTI_AGENT_001\logs\elastic_stderr.log"
set EC=%ERRORLEVEL%
echo EXITLEVEL=%EC%>> "G:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W8_KIMI_K2_MULTI_AGENT_001\run_meta_elastic.txt"
echo END_LOCAL=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\RAWRXD_ALL_BACKENDS_COMPLETE_001\W8_KIMI_K2_MULTI_AGENT_001\run_meta_elastic.txt"
endlocal
