@echo off
REM ============================================================================
REM Milestone 3: Integration Build Script
REM Builds the integrated inference pipeline with tokenizer
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set "MINGW_BIN=C:\ProgramData\mingw64\mingw64\bin"
set "SRC_ROOT=%~dp0src"
set "BUILD_DIR=%~dp0build_cli"

REM Compiler flags
set "CFLAGS=-std=c++17 -O3 -mavx2 -mfma"
set "INCLUDES=-I %SRC_ROOT% -I %SRC_ROOT%\ai -I %SRC_ROOT%\tokenizer -I %SRC_ROOT%\model -I %SRC_ROOT%\core"

echo ============================================================================
echo Milestone 3: Integration Build
echo ============================================================================
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Compile tokenizer
echo [1/4] Compiling tokenizer...
"%MINGW_BIN%\g++.exe" %CFLAGS% %INCLUDES% -c "%SRC_ROOT%\tokenizer\tokenizer.cpp" -o "%BUILD_DIR%\tokenizer.obj"
if !ERRORLEVEL! neq 0 (
    echo ERROR: tokenizer.cpp compilation failed
    exit /b 1
)
echo   tokenizer.obj
echo.

REM Compile hash chain (for checkpoint support)
echo [2/4] Compiling hash chain...
"%MINGW_BIN%\g++.exe" %CFLAGS% %INCLUDES% -c "%SRC_ROOT%\core\hash_chain.cpp" -o "%BUILD_DIR%\hash_chain.obj"
if !ERRORLEVEL! neq 0 (
    echo ERROR: hash_chain.cpp compilation failed
    exit /b 1
)
echo   hash_chain.obj
echo.

REM Compile real model caller
echo [3/4] Compiling real model caller...
"%MINGW_BIN%\g++.exe" %CFLAGS% %INCLUDES% -c "%SRC_ROOT%\ai\ai_model_caller_real.cpp" -o "%BUILD_DIR%\ai_model_caller_real.obj"
if !ERRORLEVEL! neq 0 (
    echo ERROR: ai_model_caller_real.cpp compilation failed
    exit /b 1
)
echo   ai_model_caller_real.obj
echo.

REM Compile integrated caller
echo [4/4] Compiling integrated caller...
"%MINGW_BIN%\g++.exe" %CFLAGS% %INCLUDES% -c "%SRC_ROOT%\ai\ai_model_caller_integrated.cpp" -o "%BUILD_DIR%\ai_model_caller_integrated.obj"
if !ERRORLEVEL! neq 0 (
    echo ERROR: ai_model_caller_integrated.cpp compilation failed
    exit /b 1
)
echo   ai_model_caller_integrated.obj
echo.

REM Link test executable
echo Linking Milestone3_Test.exe...
"%MINGW_BIN%\g++.exe" %CFLAGS% "%SRC_ROOT%\tests\test_milestone3_integration.cpp" ^
    "%BUILD_DIR%\tokenizer.obj" ^
    "%BUILD_DIR%\hash_chain.obj" ^
    "%BUILD_DIR%\ai_model_caller_real.obj" ^
    "%BUILD_DIR%\ai_model_caller_integrated.obj" ^
    -o "%BUILD_DIR%\Milestone3_Test.exe" ^
    -lkernel32

if !ERRORLEVEL! neq 0 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ============================================================================
echo Build Complete: %BUILD_DIR%\Milestone3_Test.exe
echo ============================================================================
echo.
echo Run with: %BUILD_DIR%\Milestone3_Test.exe
