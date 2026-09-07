@echo off
setlocal
set ROOT=F:\~dev\rawrxd
set BIN=%ROOT%\build-win32ide-p1\bin
set MODEL=%ROOT%\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
set CKPT=%BIN%\logs\p1_cpu_load_ckpt.txt
if not exist "%BIN%\logs" mkdir "%BIN%\logs"
echo === RUN p1_cpu_loadmodel_harness ===
echo model=%MODEL%
"%BIN%\p1_cpu_loadmodel_harness.exe" "%MODEL%"
set RC=%ERRORLEVEL%
echo === EXIT=%RC% ===
echo === LAST 40 CKPT LINES ===
if exist "%CKPT%" (
  powershell -NoProfile -Command "Get-Content -LiteralPath '%CKPT%' | Select-Object -Last 40"
) else (
  echo CKPT_MISSING
)
exit /b %RC%
