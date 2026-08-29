@echo off
set RAWRXD_TOKENIZER_CERT=1
set RAWRXD_GREEDY=1
cd /d "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_tokcert"
set /p TASK=<"F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_001\task_oneline.txt"
"F:\~dev\rawrxd\build-ninja\bin\RawrXD-Agentic.exe" --model "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --workspace "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_tokcert" --max-steps 1 --max-tokens 1 --no-stream --task "%TASK%" > "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_001\agent_tokenizer_cert.console.txt" 2>&1
echo AGENT_EXIT=%ERRORLEVEL%>> "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\TOKENIZER_PARITY_001\agent_tokenizer_cert.console.txt"
