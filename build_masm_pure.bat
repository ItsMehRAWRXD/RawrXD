@echo off
REM ============================================================================
REM build_masm_pure.bat - Build RawrXD with Pure MASM (Zero Dependencies)
REM ============================================================================
REM This script builds the complete inference pipeline using only:
REM   - MASM x64 (ml64.exe) for tensor operations
REM   - MSVC CL for C++ wrapper
REM   - Windows API only (no GGML, no external libs)
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set ML64_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LIB_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64
set INCLUDE_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include

set SRC_DIR=D:\RawrXD\src
set MASM_DIR=%SRC_DIR%\masm
set BUILD_DIR=D:\RawrXD\build_masm
set OUT_DIR=D:\RawrXD\bin

REM Create directories
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %OUT_DIR% mkdir %OUT_DIR%

echo ============================================================================
echo RawrXD Pure MASM Build System
echo ============================================================================
echo ML64:  %ML64_PATH%
echo CL:    %CL_PATH%
echo ============================================================================
echo.

REM Check tools exist
if not exist "%ML64_PATH%" (
    echo ERROR: ml64.exe not found at %ML64_PATH%
    exit /b 1
)

if not exist "%CL_PATH%" (
    echo ERROR: cl.exe not found at %CL_PATH%
    exit /b 1
)

set "PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64;%PATH%"

REM ============================================================================
REM STEP 1: Assemble MASM kernels
REM ============================================================================
echo [1/5] Assembling MASM kernels...

set MASM_OBJS=

REM Math kernels
echo   - rawrxd_math_masm.asm
"%ML64_PATH%" /c /Fo%BUILD_DIR%\rawrxd_math_masm.obj /W3 /nologo "%MASM_DIR%\rawrxd_math_masm.asm"
if errorlevel 1 (
    echo ERROR: Failed to assemble rawrxd_math_masm.asm
    exit /b 1
)
set MASM_OBJS=%MASM_OBJS% %BUILD_DIR%\rawrxd_math_masm.obj

REM Quantization kernels
echo   - rawrxd_quant_masm.asm
"%ML64_PATH%" /c /Fo%BUILD_DIR%\rawrxd_quant_masm.obj /W3 /nologo "%MASM_DIR%\rawrxd_quant_masm.asm"
if errorlevel 1 (
    echo ERROR: Failed to assemble rawrxd_quant_masm.asm
    exit /b 1
)
set MASM_OBJS=%MASM_OBJS% %BUILD_DIR%\rawrxd_quant_masm.obj

REM Transformer kernels
echo   - rawrxd_transformer_masm.asm
"%ML64_PATH%" /c /Fo%BUILD_DIR%\rawrxd_transformer_masm.obj /W3 /nologo "%MASM_DIR%\rawrxd_transformer_masm.asm"
if errorlevel 1 (
    echo ERROR: Failed to assemble rawrxd_transformer_masm.asm
    exit /b 1
)
set MASM_OBJS=%MASM_OBJS% %BUILD_DIR%\rawrxd_transformer_masm.obj

echo   MASM objects: %MASM_OBJS%
echo.

REM ============================================================================
REM STEP 2: Compile C++ inference engine
REM ============================================================================
echo [2/5] Compiling C++ inference engine...

set CPP_FLAGS=/O2 /W3 /EHsc /MD /nologo /DNDEBUG /DWIN32_LEAN_AND_MEAN
set CPP_FLAGS=%CPP_FLAGS% /I"%SRC_DIR%" /I"%MASM_DIR%"
set CPP_FLAGS=%CPP_FLAGS% /I"%INCLUDE_PATH%"

echo   - ai_model_caller_real.cpp
"%CL_PATH%" %CPP_FLAGS% /c /Fo%BUILD_DIR%\ai_model_caller_real.obj "%SRC_DIR%\ai_model_caller_real.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile ai_model_caller_real.cpp
    exit /b 1
)

echo   - inference_engine.cpp
echo     ^(Skipping - uses existing modules\inference_engine.cpp^)
echo.

REM ============================================================================
REM STEP 3: Compile additional C++ sources
REM ============================================================================
echo [3/5] Compiling additional sources...

REM Add other required source files here
REM Example:
REM echo   - cpu_inference_engine.cpp
REM "%CL_PATH%" %CPP_FLAGS% /c /Fo%BUILD_DIR%\cpu_inference_engine.obj "%SRC_DIR%\cpu_inference_engine.cpp"

echo   ^(Additional sources can be added here^)
echo.

REM ============================================================================
REM STEP 4: Link everything
REM ============================================================================
echo [4/5] Linking...

set LINK_FLAGS=/O2 /MD /nologo /SUBSYSTEM:CONSOLE
set LINK_FLAGS=%LINK_FLAGS% /LIBPATH:"%LIB_PATH%"
set LINK_FLAGS=%LINK_FLAGS% kernel32.lib user32.lib advapi32.lib

set OBJS=%BUILD_DIR%\ai_model_caller_real.obj %MASM_OBJS%

echo   Objects: %OBJS%
echo   Output: %OUT_DIR%\RawrXD_MASM_Pure.exe

"%CL_PATH%" %LINK_FLAGS% %OBJS% /Fe%OUT_DIR%\RawrXD_MASM_Pure.exe
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo.

REM ============================================================================
REM STEP 5: Verify output
REM ============================================================================
echo [5/5] Verifying output...

if exist "%OUT_DIR%\RawrXD_MASM_Pure.exe" (
    echo   SUCCESS: %OUT_DIR%\RawrXD_MASM_Pure.exe created
    
    REM Check dependencies
    echo   Dependencies:
    dumpbin /dependents "%OUT_DIR%\RawrXD_MASM_Pure.exe" 2>nul | findstr /V "^$" | head -20
    
    echo.
    echo ============================================================================
    echo Build Complete!
    echo ============================================================================
    echo.
    echo To test: %OUT_DIR%\RawrXD_MASM_Pure.exe
    echo.
) else (
    echo   ERROR: Output file not created
    exit /b 1
)

endlocal
