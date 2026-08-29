@echo off
set RAWRXD_GREEDY=1
set RAWRXD_TOKENIZER_CERT=1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\ws2"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\ws2" --max-steps 1 --max-tokens 16 --no-stream --task "Say hi." > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\heal2.console.txt" 2>&1
echo EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\template_heal\heal2.console.txt"
