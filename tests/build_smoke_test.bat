@echo off
:: ============================================================================
:: VAL-032: Speculative Decoder Smoke Test Build Script
:: ============================================================================

setlocal EnableDelayedExpansion

:: Tool paths (from copilot-instructions.md)
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

:: Directories
set SRC_DIR=D:\RawrXD\src
set TEST_DIR=D:\RawrXD\tests
set BUILD_DIR=D:\RawrXD\build\tests

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo ============================================================================
echo Building VAL-032 Speculative Decoder Smoke Test
echo ============================================================================

:: Step 1: Assemble the MASM kernel
echo.
echo [1/3] Assembling tree_attention_avx512.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo %BUILD_DIR%\tree_attention_avx512.obj ^
    %SRC_DIR%\kernels\tree_attention_avx512.asm

if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo Assembly successful.

:: Step 2: Compile the smoke test
echo.
echo [2/3] Compiling speculative_kernel_smoke.cpp...
"%CL%" /c /W4 /O2 /nologo /Zi /EHsc /arch:AVX512 ^
    /I %SRC_DIR% ^
    /Fo %BUILD_DIR%\speculative_kernel_smoke.obj ^
    %TEST_DIR%\speculative_kernel_smoke.cpp

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo Compilation successful.

:: Step 3: Link
echo.
echo [3/3] Linking...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB ^
    /OUT:%BUILD_DIR%\speculative_kernel_smoke.exe ^
    %BUILD_DIR%\speculative_kernel_smoke.obj ^
    %BUILD_DIR%\tree_attention_avx512.obj ^
    kernel32.lib ^
    ucrt.lib ^
    legacy_stdio_definitions.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo Linking successful.

echo.
echo ============================================================================
echo Build Complete: %BUILD_DIR%\speculative_kernel_smoke.exe
echo ============================================================================
echo.
echo To run the smoke test:
echo   %BUILD_DIR%\speculative_kernel_smoke.exe
echo.

endlocal
