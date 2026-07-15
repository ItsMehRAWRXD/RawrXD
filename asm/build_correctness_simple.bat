@echo off
:: Build Kernel Correctness Test - Simple Version
::
:: Date: July 10, 2026

echo ============================================================================
echo Kernel Correctness Test Build (Simple)
echo ============================================================================
echo.

set SRC_DIR=d:\src\asm
set OUT_DIR=%SRC_DIR%\bin

:: Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: Use VS2022 Enterprise
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    exit /b 1
)

:: Set up include paths for Windows SDK
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared

:: Set up library paths for Windows SDK
set LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64
set LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

echo [1/2] Compiling test_kernel_correctness.cpp...
cl /EHsc /O2 /W3 /nologo /MD /I. /Fo"%OUT_DIR%\test_kernel_correctness.obj" /c test_kernel_correctness.cpp
if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo     OK: test_kernel_correctness.obj

echo.
echo [2/2] Linking test executable...
link /OUT:"%OUT_DIR%\test_kernel_correctness.exe" "%OUT_DIR%\test_kernel_correctness.obj" "Sovereign_Intrinsics.lib" "Sovereign_LayerNorm.lib" "Sovereign_Legacy_Kernels.lib" "Sovereign_Q4K_Dequant.lib" "Sovereign_ResidualAdd.lib" "Sovereign_RMSNorm.lib" "Sovereign_RoPE.lib" "Sovereign_Transformer_Oracle.lib" kernel32.lib user32.lib
echo     OK: test_kernel_correctness.exe

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output: %OUT_DIR%\test_kernel_correctness.exe
echo.
