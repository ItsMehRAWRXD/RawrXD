@echo off
echo ==============================================
echo  Phi3 Mini Smoke Test - LLAMA.CPP ENGINE
echo ==============================================
set MODEL=D:\phi3mini.gguf
set ENGINE=D:\llama-direct\hip\llama-cli.exe

if not exist "%MODEL%" (
    echo [ERROR] Model %MODEL% not found!
    exit /b 1
)
if not exist "%ENGINE%" (
    echo [ERROR] Engine %ENGINE% not found!
    exit /b 1
)

echo [INFO] Running inference...
"%ENGINE%" -m "%MODEL%" -n 64 -p "System: You are an AI assistant. User: What is the sum of 2 and 2? Assistant:" -c 256 --temp 0.1

echo.
echo ==============================================
echo  Smoke test completed.
echo ==============================================
