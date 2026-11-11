@echo off
echo === Test: deepseek-r1:32b via rawr.exe ollama backend (10 min timeout) ===
set OLLAMA_NUM_PARALLEL=1
set OLLAMA_MAX_LOADED_MODELS=1
"F:\rawrxd\build\bin-msvc\Release\rawr.exe" run deepseek-r1:32b --backend ollama --max-tokens=20 --approve-mutations --goal "Say exactly: AGENT_RESULT=5" 2>&1
