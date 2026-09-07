@echo off
set RAWRXD_GREEDY=1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug"
"F:\~dev\rawrxd\build-ninja\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_04_logic_bug" --max-steps 6 --max-tokens 256 --no-stream --task-file "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\04_logic_bug\task_oneline.txt" > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\04_logic_bug\agent.console.txt" 2>&1
echo AGENT_EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\04_logic_bug\agent.console.txt"
set AGENT_EC=%ERRORLEVEL%
exit /b %AGENT_EC%
