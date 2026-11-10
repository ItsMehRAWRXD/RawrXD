@echo off
REM Generate reference tokens using llama-cli for multi-token validation
REM Usage: generate_ref_tokens.bat <num_tokens>

set MODEL=G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
set OUTDIR=F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001
set MAX_TOKENS=%1
if "%MAX_TOKENS%"=="" set MAX_TOKENS=20

echo Generating %MAX_TOKENS% reference tokens...

REM Create a prompt file with the initial token
echo 1 > %OUTDIR%\prompt.txt

REM Run llama-cli with the prompt and capture output
F:\rawrxd\tmp_llama-clone\build\bin\Release\llama-cli.exe ^
    -m %MODEL% ^
    -f %OUTDIR%\prompt.txt ^
    -n %MAX_TOKENS% ^
    --temp 0 ^
    --simple-io ^
    -c 2048 ^
    --no-display-prompt ^
    > %OUTDIR%\llama_cli_ref.log 2>&1

echo Done.