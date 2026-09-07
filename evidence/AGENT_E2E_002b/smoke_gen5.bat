@echo off
set RAWRXD_GREEDY=1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen5"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen5" --max-steps 1 --max-tokens 48 --no-stream --task "Reply with exactly the word OK and nothing else." > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen5.console.txt" 2>&1
echo EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen5.console.txt"
