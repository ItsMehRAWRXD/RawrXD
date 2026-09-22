@echo off
"F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 2 > "F:\~dev\geometry_004_ntok2.out.log" 2> "F:\~dev\geometry_004_ntok2.err.log"
echo EXIT=%ERRORLEVEL%> "F:\~dev\geometry_004_ntok2.exit.txt"
