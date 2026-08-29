@echo off
set RAWRXD_GREEDY=1
"F:\~dev\rawrxd\build-ninja\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\q4k_smoke_ws" --max-steps 1 --max-tokens 16 --no-stream --task "Reply with exactly the word OK."
