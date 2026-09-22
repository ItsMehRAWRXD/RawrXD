@echo off
color 0a
echo [=== LAUNCHING ntok=2 AUTHORITY RUN ===]
"F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 2
echo.
echo EXIT=%ERRORLEVEL%
echo.
pause
