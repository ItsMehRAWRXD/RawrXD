@echo off
setlocal EnableDelayedExpansion
set BIN=F:\~dev\rawrxd\build-win32ide-p1\bin
set MODEL=F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
set CKPT=%BIN%\logs\p1_cpu_load_ckpt.txt
echo === after-streaming harness ===
"%BIN%\p1_cpu_loadmodel_harness.exe" --after-streaming "%MODEL%"
set RC=!ERRORLEVEL!
echo === EXIT=!RC! ===
echo === LAST CKPT ===
powershell -NoProfile -Command "Get-Content -LiteralPath '%CKPT%' | Select-Object -Last 30"
exit /b %RC%
