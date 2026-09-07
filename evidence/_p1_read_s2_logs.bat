@echo off
echo === CERT ===
if exist "F:\~dev\rawrxd\build-win32ide-p1\bin\logs\p1_gguf_load_cert.txt" (
  type "F:\~dev\rawrxd\build-win32ide-p1\bin\logs\p1_gguf_load_cert.txt"
) else (
  echo MISSING
)
echo === CKPT LAST 40 ===
if exist "F:\~dev\rawrxd\build-win32ide-p1\bin\logs\p1_cpu_load_ckpt.txt" (
  powershell -NoProfile -Command "Get-Content -LiteralPath 'F:\~dev\rawrxd\build-win32ide-p1\bin\logs\p1_cpu_load_ckpt.txt' | Select-Object -Last 40"
) else (
  echo CKPT_MISSING
)
echo === EXE ===
dir "F:\~dev\rawrxd\build-win32ide-p1\bin\RawrXD-Win32IDE.exe"
exit /b 0
