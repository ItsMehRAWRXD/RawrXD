@echo off
REM ============================================================================
REM Build Script: GGUF MASM Adapter
REM ============================================================================
REM Assembles the MASM GGUF_NextTensor and builds the C++ adapter
REM ============================================================================

setlocal enabledelayedexpansion

REM Tool paths (auto-detect VS2022)
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul') do set VSPATH=%%i

if not defined VSPATH (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

set VCTools=%VSPATH%\VC\Tools\MSVC
for /f %%i in ('dir /b /ad "%VCTools%" ^| findstr /r "^[0-9]"') do set MSVCVER=%%i

set ML64="%VCTools%\%MSVCVER%\bin\Hostx64\x64\ml64.exe"
set LINK="%VCTools%\%MSVCVER%\bin\Hostx64\x64\link.exe"
set CL="%VCTools%\%MSVCVER%\bin\Hostx64\x64\cl.exe"
set LIBTOOL="%VCTools%\%MSVCVER%\bin\Hostx64\x64\lib.exe"

echo Using MSVC version: %MSVCVER%
echo.

REM Output directories
set OUTDIR=%~dp0\integration_build
if not exist %OUTDIR% mkdir %OUTDIR%

echo ============================================
echo Building GGUF MASM Adapter
echo ============================================
echo.

REM ============================================================================
REM Step 1: Assemble MASM code
REM ============================================================================
echo [1/4] Assembling GGUF_NextTensor.asm...
%ML64% /c /W3 /Zi /Fo %OUTDIR%\GGUF_NextTensor.obj GGUF_NextTensor.asm
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo      OK: %OUTDIR%\GGUF_NextTensor.obj
echo.

REM ============================================================================
REM Step 2: Compile C++ adapter
REM ============================================================================
echo [2/4] Compiling C++ adapter...
%CL% /c /O2 /W4 /EHsc /Zi /Fo %OUTDIR%\GGUF_MASM_Adapter.obj ^
    /I. ^
    GGUF_MASM_Adapter.cpp
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo      OK: %OUTDIR%\GGUF_MASM_Adapter.obj
echo.

REM ============================================================================
REM Step 3: Create static library
REM ============================================================================
echo [3/4] Creating static library...
lib /OUT:%OUTDIR%\GGUF_MASM.lib %OUTDIR%\GGUF_NextTensor.obj %OUTDIR%\GGUF_MASM_Adapter.obj
if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)
echo      OK: %OUTDIR%\GGUF_MASM.lib
echo.

REM ============================================================================
REM Step 4: Build benchmark executable (optional)
REM ============================================================================
echo [4/4] Building benchmark executable...
%CL% /O2 /W4 /EHsc /Zi /Fe %OUTDIR%\GGUF_MASM_Benchmark.exe ^
    /DGGUF_MASM_BENCHMARK ^
    /I. ^
    GGUF_MASM_Adapter.cpp ^
    %OUTDIR%\GGUF_NextTensor.obj ^
    /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo WARNING: Benchmark build failed (non-critical)
) else (
    echo      OK: %OUTDIR%\GGUF_MASM_Benchmark.exe
)
echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ============================================
echo Build Complete
echo ============================================
echo.
echo Output files:
echo   - %OUTDIR%\GGUF_NextTensor.obj    (MASM object)
echo   - %OUTDIR%\GGUF_MASM_Adapter.obj  (C++ object)
echo   - %OUTDIR%\GGUF_MASM.lib          (Static library)
echo   - %OUTDIR%\GGUF_MASM_Benchmark.exe (Benchmark tool)
echo.
echo Headers for integration:
echo   - GGUF_NextTensor.h               (Core C API)
echo   - GGUF_MASM_Adapter.h             (C++ wrapper + integration)
echo.
echo To use in your project:
echo   1. Include GGUF_MASM_Adapter.h
echo   2. Link against %OUTDIR%\GGUF_MASM.lib
echo   3. Use RawrXD::MASMStreamingBackend or RawrXD::StreamingGGUFLoaderMASM
echo.

endlocal
