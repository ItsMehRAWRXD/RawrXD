@echo off
setlocal

d:\rawrxd\test_lora_validate.exe
set EXITCODE=%ERRORLEVEL%

if %EXITCODE% EQU 0 (
    echo Shadow Run PASSED: Kernel returned success, output validated
    exit /b 0
) else if %EXITCODE% EQU 1 (
    echo Shadow Run FAILED: Kernel returned error code
    exit /b 1
) else if %EXITCODE% EQU 2 (
    echo Shadow Run FAILED: Output validation failed (NaN/Inf detected)
    exit /b 2
) else (
    echo Shadow Run UNKNOWN: Exit code %EXITCODE%
    exit /b %EXITCODE%
)
