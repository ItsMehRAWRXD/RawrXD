@echo off
set RAWRXD_GREEDY=1
cd /d "F:\~dev\rawrxd\evidence\AGENT_TOOL_SCHEMA_002\smoke\ws"
"F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_TOOL_SCHEMA_002\smoke\ws" --max-steps 2 --max-tokens 96 --no-stream --task "Fix main.c compile error. First line MUST be TOOL_CALL with strict JSON. Start: TOOL_CALL: read_file {"path":"main.c"}" > "F:\~dev\rawrxd\evidence\AGENT_TOOL_SCHEMA_002\smoke\console.txt" 2>&1
set AGENT_EC=%ERRORLEVEL%
echo AGENT_EXIT=%AGENT_EC%>> "F:\~dev\rawrxd\evidence\AGENT_TOOL_SCHEMA_002\smoke\console.txt"
exit /b %AGENT_EC%
