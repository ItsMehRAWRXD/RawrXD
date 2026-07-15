@echo off
REM Build script for SEG End-to-End Test

echo Building SEG End-to-End Test...
echo.

REM Set paths
set RUNTIME_DIR=..\runtime
set SEG_DIR=.

REM Compile
echo Compiling test_seg_end_to_end.cpp...
g++ -std=c++17 -O2 -I%RUNTIME_DIR% -I%SEG_DIR% ^
    test_seg_end_to_end.cpp ^
    %RUNTIME_DIR%\streaming_multi_layer_backend.cpp ^
    %RUNTIME_DIR%\streaming_gguf_loader.cpp ^
    %RUNTIME_DIR%\streaming_layer_registry.cpp ^
    %RUNTIME_DIR%\kv_cache.cpp ^
    %RUNTIME_DIR%\q4k_decoder.cpp ^
    seg_graph.cpp ^
    seg_models.cpp ^
    seg_executor.cpp ^
    seg_memory.cpp ^
    seg_node.cpp ^
    seg_scheduler.cpp ^
    seg_runtime.cpp ^
    -o test_seg_end_to_end.exe ^
    -lws2_32

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Build successful!
echo.
echo Usage: test_seg_end_to_end.exe ^<model.gguf^> [options]
echo.
echo Example:
echo   test_seg_end_to_end.exe phi-3-mini-q4_k.gguf --prompt "Hello" --max-tokens 5
echo.

exit /b 0
