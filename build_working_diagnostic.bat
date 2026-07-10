@echo off
REM Build diagnostic with actual kernel libraries

set GPP=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set ASM_DIR=..\src\asm

echo ===========================================
echo Building Kernel Diagnostic (with libs)
echo ===========================================
echo.

if not exist "%GPP%" (
    echo ERROR: MinGW not found
    exit /b 1
)

echo Compiling...
"%GPP%" -O2 -std=c++17 -I. -I..\src\asm diagnose_kernels_working.cpp ^
    %ASM_DIR%\Sovereign_Legacy_Kernels.lib ^
    %ASM_DIR%\Sovereign_Intrinsics.lib ^
    %ASM_DIR%\Sovereign_RMSNorm.lib ^
    %ASM_DIR%\Sovereign_ResidualAdd.lib ^
    %ASM_DIR%\Sovereign_RoPE.lib ^
    %ASM_DIR%\Sovereign_LayerNorm.lib ^
    %ASM_DIR%\Sovereign_Q4K_Dequant.lib ^
    -o diagnose_kernels_working.exe 2>&1

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo ===========================================
echo BUILD SUCCESS
echo ===========================================
echo.
echo Running diagnostic...
echo.
diagnose_kernels_working.exe

exit /b 0
