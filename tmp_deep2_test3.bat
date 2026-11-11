@echo off
echo Say exactly: AGENT_RESULT=5 > "F:\rawrxd\deep2_input.txt"
set RAWRXD_DEEP2_NUMERIC_L2_LIMIT=5.0e6
"F:\rawrxd\build\bin-msvc\Release\rawr.exe" run gemma3-1b-Q2_K.gguf --max-tokens=5 --approve-mutations < "F:\rawrxd\deep2_input.txt" > "F:\rawrxd\deep2_output.txt" 2>&1
type "F:\rawrxd\deep2_output.txt"
