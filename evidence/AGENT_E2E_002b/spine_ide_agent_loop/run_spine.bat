@echo off
set RAWRXD_GREEDY=1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
"F:\~dev\rawrxd\build-win32ide-fresh\bin\ide_agent_loop_cert.exe" --mode deep2 --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --fixture "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\spine_ide_agent_loop\fixture" > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\spine_ide_agent_loop\spine.console.txt" 2>&1
echo SPINE_EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\spine_ide_agent_loop\spine.console.txt"
