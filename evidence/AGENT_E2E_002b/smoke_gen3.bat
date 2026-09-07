@echo off
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen3"
set RAWRXD_GREEDY=1
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen3" --max-steps 1 --max-tokens 48 --no-stream --task "Reply with exactly the word OK." > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen3.console.txt" 2>&1
