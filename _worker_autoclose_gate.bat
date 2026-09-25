@echo off
setlocal EnableDelayedExpansion
set "buildDir=f:\~dev\rawrxd\win32ide_strict\build_v4"
set "exe=f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe"
set "model=D:\rawrxd\gemma3-1b-Q2_K.gguf"
set "receipt=f:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_autoclose.txt"

echo [WORKER] Building...
cd /d "%buildDir%"
cmake --build . --config Release --target RawrXD-Win32IDE
if errorlevel 1 (
    echo [WORKER] BUILD FAILED
    exit /b 1
)
echo [WORKER] Build OK

echo [WORKER] Running autoclose gate...
"%exe%" --autoclose --model "%model%" --workspace "f:\~dev\rawrxd" --gate-tokens 8 --nonce "7E91B462" --receipt "%receipt%" --wall-ms 300000
echo [WORKER] Gate exit code: %errorlevel%

if exist "%receipt%" (
    echo [WORKER] RECEIPT CONTENT:
    type "%receipt%"
    findstr "VERDICT=PASS" "%receipt%" >nul && echo [WORKER] CERTIFICATION PASS || echo [WORKER] CERTIFICATION FAIL
) else (
    echo [WORKER] NO RECEIPT
)
