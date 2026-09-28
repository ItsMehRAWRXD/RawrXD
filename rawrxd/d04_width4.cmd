@echo off
:: D04-A Width 4 Certification
:: Set environment variable for D04 batch width
set DEEP2_D04_BATCH_WIDTH=4
echo DEEP2_D04_BATCH_WIDTH=%DEEP2_D04_BATCH_WIDTH%

:: Run the gate executable with width 4
echo Running D04-A width 4 test...
F:\~dev\build_streaming\Release\deep2_185in30_gate.exe "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" > F:\~dev\d04_width4.txt 2>&1
echo D04 width 4 test complete.
echo Output written to F:\~dev\d04_width4.txt