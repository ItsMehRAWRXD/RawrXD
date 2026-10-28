@echo off
setlocal
mkdir "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001" 2>nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001\bin"
set LOCAL_ONLY=1
set RAWRXD_HEADLESS=1
echo START_UTC=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001\run_meta_partial.txt"
RawrXD-Win32IDE.exe --headless --local --no-server --model G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose > "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001\raw_stdout.log" 2> "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001\raw_stderr.log"
echo EXITLEVEL=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001\run_meta_partial.txt"
echo END_UTC=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\LIVE_TETRAD_POST_CAMELLIA_001\run_meta_partial.txt"
echo DONE
endlocal
