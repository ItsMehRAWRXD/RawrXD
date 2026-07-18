@echo off
echo RawrXD Validation Script
echo ========================
echo.
echo Running validation tests...
echo.

cd tests

if exist test_gguf_minimal.exe (
    echo [VAL-017] GGUF Minimal...
    test_gguf_minimal.exe
    if errorlevel 1 echo FAILED
)

if exist smoke_core.exe (
    echo [VAL-016] Core Smoke...
    smoke_core.exe
    if errorlevel 1 echo FAILED
)

if exist test_gate_d_intrinsics.exe (
    echo [VAL-018] Gate D Kernels...
    test_gate_d_intrinsics.exe
    if errorlevel 1 echo FAILED
)

cd ..
echo.
echo Validation complete.
pause
