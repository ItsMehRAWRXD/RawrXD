@echo off
REM ============================================================================
REM RawrXD Phase 4: GGML Integration Build Script
REM ============================================================================
REM This script compiles the inference module with GGML integration
REM 
REM Requirements:
REM   - MinGW-w64 or MSVC with C++17 support
REM   - GGML headers in ../../3rdparty/ggml/include
REM   - GGML library (optional - for full linking)
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set "SRC_DIR=%~dp0"
set "ROOT_DIR=%SRC_DIR%\..\.."
set "GGML_DIR=%ROOT_DIR%\3rdparty\ggml"
set "BUILD_DIR=%ROOT_DIR%\build_inference"
set "OUTPUT_DIR=%BUILD_DIR%\bin"

REM Compiler settings
set "CXX=g++"
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -I%SRC_DIR% -I%GGML_DIR%\include"
set "LDFLAGS=-pthread"

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ============================================================================
echo RawrXD Phase 4: GGML Integration Build
echo ============================================================================
echo.
echo Configuration:
echo   Source: %SRC_DIR%
echo   GGML:   %GGML_DIR%
echo   Build:  %BUILD_DIR%
echo   Output: %OUTPUT_DIR%
echo.

REM Source files
set "SOURCES="
set "SOURCES=!SOURCES! %SRC_DIR%\InferenceEngine.cpp"
set "SOURCES=!SOURCES! %SRC_DIR%\LegacyInferenceAdapter.cpp"
set "SOURCES=!SOURCES! %SRC_DIR%\GGMLBackend.cpp"
set "SOURCES=!SOURCES! %SRC_DIR%\GGMLForwardPass.cpp"
set "SOURCES=!SOURCES! %SRC_DIR%\ModelLoader.cpp"

echo Building inference module...
echo.

REM Compile object files
set "OBJ_FILES="
for %%f in (!SOURCES!) do (
    set "SRC_FILE=%%f"
    set "OBJ_FILE=%BUILD_DIR%\%%~nf.o"
    set "OBJ_FILES=!OBJ_FILES! !OBJ_FILE!"
    
    echo Compiling %%~nf.cpp...
    %CXX% %CXXFLAGS% -c "!SRC_FILE!" -o "!OBJ_FILE!"
    
    if errorlevel 1 (
        echo ERROR: Failed to compile %%~nf.cpp
        exit /b 1
    )
)

echo.
echo Creating static library...

REM Create static library
set "LIB_FILE=%OUTPUT_DIR%\libRawrXD_Inference.a"
ar rcs "!LIB_FILE!" !OBJ_FILES!

if errorlevel 1 (
    echo ERROR: Failed to create library
    exit /b 1
)

echo.
echo ============================================================================
echo Build Complete!
echo ============================================================================
echo.
echo Output: !LIB_FILE!
echo.
echo Object files:
for %%f in (!OBJ_FILES!) do (
    echo   - %%~nxf
)
echo.
echo Next steps:
echo   1. Link with GGML library: -lggml
echo   2. Create test executable
echo   3. Run integration tests
echo.

endlocal
