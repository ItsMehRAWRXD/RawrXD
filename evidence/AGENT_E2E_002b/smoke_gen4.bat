@echo off
set RAWRXD_GREEDY=1
set RAWRXD_DEEP2_LAYER_PROBE=
set RAWRXD_B3_TRACE=
set RAWRXD_LINEARW_TRACE=
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen4"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen4" --max-steps 1 --max-tokens 64 --no-stream --task "Reply with exactly the word OK and nothing else." > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\smoke_gen4.console.txt" 2>&1
echo EXIT=!ERRORLEVEL!
