@echo off
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen2"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen2" --max-steps 1 --max-tokens 32 --no-stream --task "Say OK" > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen2.console.txt" 2>&1
