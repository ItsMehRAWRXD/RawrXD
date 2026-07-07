@echo off
REM Build script for MASM kernels
REM Compiles .asm files to .obj for linking

echo ========================================
echo Building MASM Kernels
echo ========================================

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at %ML64%
    echo Please install Visual Studio 2022 with C++ build tools
    exit /b 1
)

echo Using: %ML64%
echo.

REM Build Softmax AVX2
echo Building softmax_avx2.asm...
"%ML64%" /c /W3 /nologo /Fo softmax_avx2.obj softmax_avx2.asm
if %ERRORLEVEL% neq 0 (
    echo FAILED: softmax_avx2.asm
    exit /b 1
)
echo SUCCESS: softmax_avx2.obj

REM Build SiLU AVX-512
echo Building silu_avx512.asm...
"%ML64%" /c /W3 /nologo /Fo silu_avx512.obj silu_avx512.asm
if %ERRORLEVEL% neq 0 (
    echo FAILED: silu_avx512.asm
    exit /b 1
)
echo SUCCESS: silu_avx512.obj

echo.
echo ========================================
echo All kernels built successfully
echo ========================================

exit /b 0
