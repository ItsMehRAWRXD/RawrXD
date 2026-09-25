@echo off
setlocal EnableDelayedExpansion
set "buildDir=f:\~dev\rawrxd\win32ide_strict\build_v4"
set "exe=f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe"
set "model=D:\rawrxd\gemma3-1b-Q2_K.gguf"
set "receipt=f:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_autoclose.txt"
set "out=f:\~dev\autoclose_gate_out.txt"
set "err=f:\~dev\autoclose_gate_err.txt"

echo [WORKER] Building...
cd /d "%buildDir%"
cmake --build . --config Release --target RawrXD-Win32IDE > "%out%.build" 2>&1
if errorlevel 1 (
    echo [WORKER] BUILD FAILED
    type "%out%.build"
    exit /b 1
)
echo [WORKER] Build OK

echo [WORKER] Running autoclose gate... > "%out%"
echo [WORKER] Running autoclose gate... > "%err%"
"%exe%" --autoclose --model "%model%" --workspace "f:\~dev\rawrxd" --gate-tokens 8 --nonce "7E91B462" --receipt "%receipt%" --wall-ms 300000 >> "%out%" 2>> "%err%"
echo [WORKER] Gate exit code: %errorlevel%
if exist "%receipt%" (
    echo [WORKER] RECEIPT:
    type "%receipt%"
) else (
    echo [WORKER] NO RECEIPT
)
