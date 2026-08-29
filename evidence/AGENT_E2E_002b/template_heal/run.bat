@echo off
set RAWRXD_GREEDY=1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\ws"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\ws" --max-steps 1 --max-tokens 48 --no-stream --task "Reply with TOOL_CALL: read_file {\"path\":\"main.c\"} as your entire answer." > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\heal.console.txt" 2>&1
echo EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\heal.console.txt"
