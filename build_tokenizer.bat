@echo off
REM RawrXD Tokenizer Build Script
REM Builds tokenizer module and runs tests

echo ============================================
echo RawrXD Tokenizer Build
echo ============================================
echo.

set SRC_DIR=d:\rawrxd\src
set BUILD_DIR=d:\rawrxd\build_cli
set CC=C:\ProgramData\mingw64\mingw64\bin\g++.exe

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Building tokenizer module...
"%CC%" -std=c++17 -O3 -mavx2 -mfma -I"%SRC_DIR%" -I"%SRC_DIR%\tokenizer" -c "%SRC_DIR%\tokenizer\tokenizer.cpp" -o "%BUILD_DIR%\tokenizer.obj" 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Tokenizer compilation failed
    exit /b 1
)
echo   ✓ tokenizer.obj

echo.
echo [2/4] Building unit tests...
"%CC%" -std=c++17 -O3 -mavx2 -mfma -I"%SRC_DIR%" -I"%SRC_DIR%\tokenizer" "%SRC_DIR%\tokenizer\test_tokenizer.cpp" "%BUILD_DIR%\tokenizer.obj" -o "%BUILD_DIR%\test_tokenizer.exe" 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Unit test compilation failed
    exit /b 1
)
echo   ✓ test_tokenizer.exe

echo.
echo [3/4] Building integration test...
"%CC%" -std=c++17 -O3 -mavx2 -mfma -I"%SRC_DIR%" -I"%SRC_DIR%\tokenizer" -I"%SRC_DIR%\model" "%SRC_DIR%\tokenizer\test_integration.cpp" "%BUILD_DIR%\tokenizer.obj" "%BUILD_DIR%\ModelLoader.obj" -o "%BUILD_DIR%\test_tokenizer_integration.exe" 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Integration test compilation failed (may need ModelLoader)
    echo   Continuing with unit tests only...
) else (
    echo   ✓ test_tokenizer_integration.exe
)

echo.
echo [4/4] Running unit tests...
"%BUILD_DIR%\test_tokenizer.exe"
if %errorlevel% neq 0 (
    echo [ERROR] Unit tests failed
    exit /b 1
)

echo.
echo ============================================
echo Tokenizer Build Complete
echo ============================================
echo.
echo Artifacts:
echo   - tokenizer.obj
echo   - test_tokenizer.exe
echo   - test_tokenizer_integration.exe (if ModelLoader available)
echo.
echo Next steps:
echo   1. Run integration test: test_tokenizer_integration.exe ^<model.gguf^>
echo   2. Integrate into ai_model_caller_real.cpp
echo   3. Run end-to-end inference with text prompts
