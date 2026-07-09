@echo off
REM ============================================================================
REM Build SEG Integration for RawrXD
REM ============================================================================
REM Builds SEG as a static library and links with rawrxd
REM ============================================================================

setlocal enabledelayedexpansion

echo ==========================================
echo SEG Integration Build for RawrXD
echo ==========================================
echo.

REM Directories
set SEG_DIR=D:\src\seg
set RUNTIME_DIR=D:\src\runtime
set RAWRXD_DIR=D:\rawrxd
set BUILD_DIR=%RAWRXD_DIR%\build_seg

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM ============================================================================
REM Step 1: Compile MASM telemetry
REM ============================================================================
echo [1/4] Compiling MASM telemetry...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\telemetry_masm.obj" "%RUNTIME_DIR%\telemetry_masm.asm"
if errorlevel 1 (
    echo FAILED: MASM compilation failed
    exit /b 1
)
echo      OK: telemetry_masm.obj

REM ============================================================================
REM Step 2: Compile SEG library sources
REM ============================================================================
echo.
echo [2/4] Compiling SEG library...

set SEG_SOURCES=
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_node.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_graph.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_scheduler.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_memory.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_executor.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_agent.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_runtime.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_models.cpp"
set SEG_SOURCES=%SEG_SOURCES% "%SEG_DIR%\seg_telemetry_view.cpp"

set RUNTIME_SOURCES=
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\streaming_multi_layer_backend.cpp"
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\streaming_gguf_loader.cpp"
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\streaming_layer_registry.cpp"
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\kv_cache.cpp"
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\q4k_decoder.cpp"
set RUNTIME_SOURCES=%RUNTIME_SOURCES% "%RUNTIME_DIR%\telemetry_stub.cpp"

REM Compile all sources to object files
set OBJ_FILES=

for %%f in (%SEG_SOURCES%) do (
    set OBJ_FILE=%BUILD_DIR%\%%~nf.obj
    set OBJ_FILES=!OBJ_FILES! "!OBJ_FILE!"
    
    g++ -std=c++17 -O2 -mavx2 -mfma -I"%SEG_DIR%" -I"%RUNTIME_DIR%" -c %%f -o "!OBJ_FILE!"
    if errorlevel 1 (
        echo FAILED: Compilation failed for %%f
        exit /b 1
    )
    echo      OK: %%~nf.obj
)

for %%f in (%RUNTIME_SOURCES%) do (
    set OBJ_FILE=%BUILD_DIR%\%%~nf.obj
    set OBJ_FILES=!OBJ_FILES! "!OBJ_FILE!"
    
    g++ -std=c++17 -O2 -mavx2 -mfma -I"%SEG_DIR%" -I"%RUNTIME_DIR%" -c %%f -o "!OBJ_FILE!"
    if errorlevel 1 (
        echo FAILED: Compilation failed for %%f
        exit /b 1
    )
    echo      OK: %%~nf.obj
)

REM ============================================================================
REM Step 3: Create static library
REM ============================================================================
echo.
echo [3/4] Creating static library...

ar rcs "%BUILD_DIR%\libseg.a" %OBJ_FILES% "%BUILD_DIR%\telemetry_masm.obj"
if errorlevel 1 (
    echo FAILED: Library creation failed
    exit /b 1
)
echo      OK: libseg.a

REM ============================================================================
REM Step 4: Build rawrxd with SEG
REM ============================================================================
echo.
echo [4/4] Building rawrxd with SEG integration...

cd /d "%RAWRXD_DIR%"

g++ -std=c++17 -O2 -mavx2 -mfma -I. -I./src -I./kernels -I"%SEG_DIR%" -I"%RUNTIME_DIR%" ^
    src\cli\unified_cli_v3_real.cpp ^
    src\execution\execution_gateway_impl.cpp ^
    src\execution\kernel_validator.cpp ^
    src\model\model_context.cpp ^
    src\runtime\tokenizer_runtime.cpp ^
    src\gateway\seg_gateway.cpp ^
    kernels\kernel_registry.cpp ^
    kernels\fused_quant_gemm.cpp ^
    kernels\compression_codec.cpp ^
    "%BUILD_DIR%\libseg.a" ^
    -o rawrxd_v3_seg.exe ^
    -lws2_32

if errorlevel 1 (
    echo FAILED: rawrxd build failed
    exit /b 1
)

echo      OK: rawrxd_v3_seg.exe

REM ============================================================================
echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Output: %RAWRXD_DIR%\rawrxd_v3_seg.exe
echo.
echo Usage:
echo   rawrxd_v3_seg.exe run model.gguf "prompt" --max-tokens 10
echo   rawrxd_v3_seg.exe run model.gguf "prompt" --dump-telemetry
echo.

endlocal
