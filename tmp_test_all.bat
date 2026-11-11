@echo off
echo === Test 1: Ollama direct HTTP API ===
curl -s -X POST http://127.0.0.1:11434/v1/chat/completions -H "Content-Type: application/json" -d "{\"model\":\"qwen3:8b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say exactly: AGENT_RESULT=5\"}],\"stream\":false,\"max_tokens\":10}" 2>&1
echo.
echo === Test 2: rawr.exe qwen3:8b via ollama backend ===
"F:\rawrxd\build\bin-msvc\Release\rawr.exe" run qwen3:8b --backend ollama --max-tokens=10 --approve-mutations --goal "Say exactly: AGENT_RESULT=5" 2>&1
echo.
echo === Test 3: rawr.exe deepseek-r1:32b via ollama backend ===
"F:\rawrxd\build\bin-msvc\Release\rawr.exe" run deepseek-r1:32b --backend ollama --max-tokens=10 --approve-mutations --goal "Say exactly: AGENT_RESULT=5" 2>&1
