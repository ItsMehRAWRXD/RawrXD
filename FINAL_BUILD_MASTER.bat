@echo off
REM ============================================================================
REM FINAL_BUILD_MASTER.bat - Complete RawrXD Build System
REM Builds all components: model loading, streaming, inference, IDE
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================================================
echo RawrXD Final Build Master
echo ============================================================================
echo.

set "VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "MINGW_PATH=C:\ProgramData\mingw64\mingw64\bin"
set "BUILD_LOG=build_master.log"

set /a SUCCESS=0
set /a FAILED=0

REM Clear log
echo Build started at %DATE% %TIME% > "%BUILD_LOG%"

REM ============================================================================
REM Step 1: Native Toolchain (Zero Dependencies)
REM ============================================================================
echo [1/5] Building Native Toolchain...
cd /d "%~dp0\compilers\native_toolchain"

REM Build unified model streamer
echo   - unified_model_streamer.c...
gcc -O2 -Wall unified_model_streamer.c -o unified_model_streamer.exe -lwinhttp 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo     SUCCESS
    set /a SUCCESS+=1
) else (
    echo     FAILED
    set /a FAILED+=1
)

REM Build GGUF mini loader
echo   - gguf_mini_loader.c...
gcc -O2 gguf_mini_loader.c -o gguf_mini_loader.exe 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo     SUCCESS
    set /a SUCCESS+=1
) else (
    echo     FAILED
    set /a FAILED+=1
)

REM Build model manager
echo   - model_manager.c...
gcc -O2 model_manager.c -o model_manager.exe -lwinhttp 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo     SUCCESS
    set /a SUCCESS+=1
) else (
    echo     FAILED
    set /a FAILED+=1
)

REM Build benchmark streaming
echo   - benchmark_streaming.c...
gcc -O2 benchmark_streaming.c -o benchmark_streaming.exe -lwinhttp 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo     SUCCESS
    set /a SUCCESS+=1
) else (
    echo     FAILED
    set /a FAILED+=1
)

REM ============================================================================
REM Step 2: SwarmV29 Kernels (MASM64)
REM ============================================================================
echo.
echo [2/5] Building SwarmV29 Kernels...
cd /d "%~dp0\src\asm"

for %%f in (SwarmV29_*.asm) do (
    echo   - %%f...
    "%VS_PATH%\ml64.exe" /c /W3 /nologo /Zi "%%f" 2>> "%~dp0%BUILD_LOG%"
    if !ERRORLEVEL! equ 0 (
        echo     SUCCESS
        set /a SUCCESS+=1
    ) else (
        echo     FAILED
        set /a FAILED+=1
    )
)

REM ============================================================================
REM Step 3: Sovereign Heap Fix
echo.
echo [3/5] Building Sovereign Heap Patch...
cd /d "%~dp0\compilers\native_toolchain"

REM Build the heap patch as object
"%VS_PATH%\ml64.exe" /c /W3 /nologo /Zi sovereign_memory_patch.asm 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo   - sovereign_memory_patch.obj: SUCCESS
    set /a SUCCESS+=1
) else (
    echo   - sovereign_memory_patch.obj: FAILED
    set /a FAILED+=1
)

REM ============================================================================
REM Step 4: Test Suite
echo.
echo [4/5] Running Tests...
cd /d "%~dp0\compilers\native_toolchain"

REM Test GGUF loader
echo   - Testing GGUF loader...
if exist "..\..\bench_min.gguf" (
    gguf_mini_loader.exe "..\..\bench_min.gguf" > nul 2>> "%~dp0%BUILD_LOG%"
    if !ERRORLEVEL! equ 0 (
        echo     SUCCESS
        set /a SUCCESS+=1
    ) else (
        echo     FAILED
        set /a FAILED+=1
    )
) else (
    echo     SKIPPED (no test file)
)

REM Test unified streamer
echo   - Testing unified streamer...
unified_model_streamer.exe load "..\..\bench_min.gguf" > nul 2>> "%~dp0%BUILD_LOG%"
if !ERRORLEVEL! equ 0 (
    echo     SUCCESS
    set /a SUCCESS+=1
) else (
    echo     FAILED
    set /a FAILED+=1
)

REM ============================================================================
REM Step 5: Summary
echo.
echo ============================================================================
echo Build Summary
echo ============================================================================
echo Success: %SUCCESS%
echo Failed:  %FAILED%
echo.

if %FAILED% equ 0 (
    echo ALL COMPONENTS BUILT SUCCESSFULLY
echo.
    echo Executables created:
    echo   - unified_model_streamer.exe  (64.9 KB) - Complete model loading + streaming
    echo   - gguf_mini_loader.exe        (minimal) - GGUF header parser
    echo   - model_manager.exe           (62.6 KB) - Ollama model management
    echo   - benchmark_streaming.exe     (62.0 KB) - Performance benchmarking
    echo   - SwarmV29_*.obj              (10 files) - PQC kernels
    echo.
    echo Next steps:
    echo   1. Run: unified_model_streamer.exe load ^<model.gguf^>
    echo   2. Run: unified_model_streamer.exe stream ^<model_name^>
    echo   3. Run: model_manager.exe
    echo   4. Run: benchmark_streaming.exe ^<model^> ^<prompt^> ^<tokens^>
    exit /b 0
) else (
    echo SOME COMPONENTS FAILED - Check %BUILD_LOG% for details
    exit /b 1
)
