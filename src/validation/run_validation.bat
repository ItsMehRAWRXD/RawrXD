@echo off
REM Model Stack Integration Validation Runner
REM This script builds and runs the validation harness

echo === Model Stack Integration Validation Runner ===
echo.

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.x
    exit /b 1
)

REM Check for CMake
cmake --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: CMake not found. Please install CMake
    exit /b 1
)

REM Generate minimal GGUF
echo [Step 1] Generating minimal GGUF file...
python minimal_gguf_generator.py test_model.gguf
if errorlevel 1 (
    echo ERROR: Failed to generate GGUF file
    exit /b 1
)
echo   ✅ GGUF file generated successfully
echo.

REM Create build directory
if not exist build mkdir build
cd build

REM Configure CMake
echo [Step 2] Configuring CMake...
cmake .. -DENABLE_AVX512=ON
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    cd ..
    exit /b 1
)
echo   ✅ CMake configured successfully
echo.

REM Build
echo [Step 3] Building validation harness...
cmake --build . --config Release
if errorlevel 1 (
    echo ERROR: Build failed
    cd ..
    exit /b 1
)
echo   ✅ Build completed successfully
echo.

REM Run validation
echo [Step 4] Running validation...
echo.
model_stack_validation.exe ..\test_model.gguf
if errorlevel 1 (
    echo.
    echo ❌ Validation failed
    cd ..
    exit /b 1
)

echo.
echo ✅ All validation phases passed successfully!
cd ..
exit /b 0