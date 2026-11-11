@echo off
echo === Deep2 Native Generation Verification ===
set RAWRXD_DEEP2_NUMERIC_L2_LIMIT=5.0e6
echo Say exactly: AGENT_RESULT=5 | "F:\rawrxd\build\bin-msvc\Release\rawr.exe" run gemma3-1b-Q2_K.gguf --max-tokens=5 --approve-mutations
