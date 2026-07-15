@echo off
REM Build RawrXD with validation hooks enabled
REM This enables llama.cpp numerical parity testing

echo ==========================================
echo RawrXD Build with Validation Hooks
echo ==========================================
echo.

set BUILD_DIR=build_validation
set CMAKE_ARGS=-DCMAKE_BUILD_TYPE=Release -DRAWRXD_ENABLE_VALIDATION=ON

echo Build directory: %BUILD_DIR%
echo CMake args: %CMAKE_ARGS%
echo.

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

cd %BUILD_DIR%

echo [1/3] Configuring...
cmake .. %CMAKE_ARGS%
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo.
echo [2/3] Building...
cmake --build . --config Release -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo [3/3] Done!
echo.
echo Validation-enabled binary: %BUILD_DIR%\Release\rawrxd.exe
echo.
echo To generate reference data from llama.cpp:
echo   python tests\inference_validation\scripts\generate_reference_data.py --model ^<model.gguf^>
echo.
echo To compare outputs:
echo   validation_runner --reference rawrxd_ref_^<model^>.bin --actual rawrxd_output.bin
