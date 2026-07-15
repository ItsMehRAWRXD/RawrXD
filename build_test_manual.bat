@echo off
REM Build script for test_quantized_real_model.cpp
REM Uses cl.exe directly without CMake

echo Building test_quantized_real_model.exe...

set SRC_DIR=D:\rawrxd\src
set TEST_DIR=D:\rawrxd\tests
set BUILD_DIR=D:\rawrxd\build_manual

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Use VS18 directly
set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: Visual Studio not found at "%VS_PATH%"
    exit /b 1
)

REM Setup environment - use call to inherit environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

REM Set library paths explicitly
set LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;%VS_PATH%\VC\Tools\MSVC\14.51.36231\lib\x64;%LIB%

REM Compile
cl.exe /std:c++20 /EHsc /O2 /W2 /arch:AVX2 /nologo ^
    /I"D:\rawrxd" ^
    /I"D:\rawrxd\src" ^
    /I"D:\rawrxd\include" ^
    /Fe"%BUILD_DIR%\test_quantized_real_model.exe" ^
    "%TEST_DIR%\test_quantized_real_model.cpp" ^
    "%SRC_DIR%\quantization\quantized_model.cpp" ^
    "%SRC_DIR%\quantization\quantized_inference.cpp" ^
    "%SRC_DIR%\quantization\quantized_transformer_layer.cpp" ^
    "%SRC_DIR%\quantization\gguf_loader.cpp"

if %ERRORLEVEL% neq 0 (
    echo Build FAILED
    exit /b 1
)

echo Build SUCCESS: %BUILD_DIR%\test_quantized_real_model.exe
echo.
echo To run: %BUILD_DIR%\test_quantized_real_model.exe [path_to_model.gguf]
