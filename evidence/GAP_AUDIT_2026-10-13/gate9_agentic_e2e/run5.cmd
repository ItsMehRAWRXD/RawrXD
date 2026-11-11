@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd\agentic_ws
"F:\rawrxd\build_gate4\bin\Release\deep2_agentic_loop.exe" --model "F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf" --workdir . --max-steps 12 --max-new 200 > "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate9_agentic_e2e\run5.log" 2>&1
echo EXIT_CODE=%errorlevel% >> "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate9_agentic_e2e\run5.log"
