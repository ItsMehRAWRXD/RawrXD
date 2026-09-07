@echo off
setlocal EnableDelayedExpansion
set EXE=F:\~dev\rawrxd\build-win32ide-p1\bin\RawrXD-Win32IDE.exe
set MODEL=F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
set BINLOG=F:\~dev\rawrxd\build-win32ide-p1\bin\logs
set CERT=%BINLOG%\p1_gguf_load_cert.txt
set CKPT=%BINLOG%\p1_cpu_load_ckpt.txt
if not exist "%BINLOG%" mkdir "%BINLOG%"

for /f "delims=" %%I in ('powershell -NoProfile -Command "[Environment]::GetFolderPath('ApplicationData')"') do set APPDATA_REAL=%%I
set SDIR=%APPDATA_REAL%\RawrXD
if not exist "%SDIR%" mkdir "%SDIR%"
(
echo {
echo   "version": 2,
echo   "schemaVersion": "2.2",
echo   "loadedModelPath": "%MODEL:\=\\%"
echo }
) > "%SDIR%\session.json"
echo SESSION=%SDIR%\session.json
type "%SDIR%\session.json"

del /f /q "%CERT%" >nul 2>&1
del /f /q "%CKPT%" >nul 2>&1

echo === launching IDE for S2 ===
start "" /D "F:\~dev\rawrxd\build-win32ide-p1\bin" "%EXE%"
set /a waits=0
:waitloop
ping -n 3 127.0.0.1 >nul
set /a waits+=1
if exist "%CERT%" (
  findstr /c:"MODEL_READY" "%CERT%" >nul 2>&1 && goto done
  findstr /c:"INFERENCE_ENGINE_CREATED" "%CERT%" >nul 2>&1 && goto done
)
if exist "%CKPT%" (
  findstr /c:"IDE_LoadModel" "%CKPT%" >nul 2>&1 && goto done
  findstr /c:"HARNESS_PASS" "%CKPT%" >nul 2>&1 && goto done
  findstr /c:"CIE_LoadModel" "%CKPT%" >nul 2>&1 && goto done
)
if %waits% GEQ 40 goto done
goto waitloop

:done
echo === waits=%waits% ===
echo === CERT ===
if exist "%CERT%" (type "%CERT%") else (echo CERT_MISSING)
echo === CKPT last 40 ===
if exist "%CKPT%" (
  powershell -NoProfile -Command "Get-Content -LiteralPath '%CKPT%' | Select-Object -Last 40"
) else (
  echo CKPT_MISSING
)
taskkill /F /IM RawrXD-Win32IDE.exe >nul 2>&1
exit /b 0
