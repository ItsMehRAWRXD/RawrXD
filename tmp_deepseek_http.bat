@echo off
echo === Test: Ollama direct HTTP with deepseek-r1:32b ===
curl -s -X POST http://127.0.0.1:11434/v1/chat/completions -H "Content-Type: application/json" -d "{\"model\":\"deepseek-r1:32b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say exactly: AGENT_RESULT=5\"}],\"stream\":false,\"max_tokens\":20}" 2>&1
