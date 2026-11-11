@echo off
echo "Say exactly: AGENT_RESULT=5" | "F:\rawrxd\build\bin-msvc\Release\rawr.exe" run gemma3-1b-Q2_K.gguf --max-tokens=10 --approve-mutations > "F:\rawrxd\tmp_deep2_output.txt" 2>&1
type "F:\rawrxd\tmp_deep2_output.txt"
