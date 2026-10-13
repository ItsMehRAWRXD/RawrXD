@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd\agentic_ws
"F:\rawrxd\build_gate4\bin\Release\deep2_agentic_loop.exe" --model "F:\rawrxd\llama3.2-3b-Q3_K_S.gguf" --workdir . --max-steps 12 --max-new 200 > "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate9_agentic_e2e\run8.log" 2>&1
echo EXIT_CODE=%errorlevel% >> "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate9_agentic_e2e\run8.log"
