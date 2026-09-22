@echo off
color 0A
echo [=== NTOK=3 / BATCH=2 DOWN AUTHORITY ===]
"F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 3
set RC=%ERRORLEVEL%
echo.
echo EXIT=%RC%
echo EXIT_HEX requires PowerShell conversion if nonzero
echo.
pause
