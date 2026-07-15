@echo off
REM ============================================================================
REM Build Script for GGUF Adapter Bridge v2
REM Enhanced Streaming Runtime Integration
REM ============================================================================

echo Building GGUF Adapter Bridge v2...
echo.

REM Set paths
set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "OUT_DIR=D:\rawrxd\sovereign\build"
set "SRC_DIR=D:\rawrxd\sovereign"

REM Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM Check for existing MASM object
if not exist "%OUT_DIR%\gguf_adapter.obj" (
    echo ERROR: gguf_adapter.obj not found!
    echo Please run build_gguf_adapter.bat first to assemble the MASM source.
    exit /b 1
)

REM Build test_streaming_loader.cpp
echo [1/2] Compiling test_streaming_loader.cpp...
cl.exe /nologo /O2 /W4 /EHsc /std:c++17 /I"%SRC_DIR%" ^
    /Fe"%OUT_DIR%\test_streaming_loader.exe" ^
    /Fo"%OUT_DIR%\test_streaming_loader.obj" ^
    "%SRC_DIR%\test_streaming_loader.cpp" ^
    /link "%OUT_DIR%\gguf_adapter.obj" kernel32.lib

if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)

REM Build original test as well
echo [2/2] Compiling test_gguf_adapter.cpp...
cl.exe /nologo /O2 /W4 /EHsc /I"%SRC_DIR%" ^
    /Fe"%OUT_DIR%\test_gguf_adapter.exe" ^
    /Fo"%OUT_DIR%\test_gguf_adapter.obj" ^
    "%SRC_DIR%\test_gguf_adapter.cpp" ^
    /link "%OUT_DIR%\gguf_adapter.obj" kernel32.lib

if errorlevel 1 (
    echo WARNING: test_gguf_adapter build failed, but streaming loader succeeded.
)

echo.
echo ============================================================================
echo Build SUCCESSFUL!
echo.
echo Output files:
echo   - %OUT_DIR%\test_streaming_loader.exe  (Enhanced streaming loader)
echo   - %OUT_DIR%\test_gguf_adapter.exe      (Basic adapter test)
echo.
echo Usage examples:
echo   test_streaming_loader.exe D:\test_model.gguf list
echo   test_streaming_loader.exe D:\test_model.gguf weights
echo   test_streaming_loader.exe D:\test_model.gguf find token_embd.weight
echo   test_streaming_loader.exe D:\test_model.gguf bench
echo   test_streaming_loader.exe D:\test_model.gguf info
echo ============================================================================

exit /b 0
