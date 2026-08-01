@echo off
REM run_inference.cmd — Run real GGUF model inference
D:\rawrxd-ci-bootstrap\build\bin\test_inference.exe "D:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" "Explain what a tensor is in one sentence."
if errorlevel 1 (
    echo INFERENCE FAILED
    pause
    exit /b 1
)
echo INFERENCE COMPLETE
pause
