@echo off
REM ============================================================================
REM RawrXD Complete Build Script
REM Builds all inference components and creates test executable
REM ============================================================================

setlocal EnableDelayedExpansion

set "CXX=g++"
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra"
set "INCLUDES=-I. -I../../3rdparty/ggml/include"
set "LDFLAGS=-pthread"

set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\build"
set "BIN_DIR=%BUILD_DIR%\bin"

echo ============================================================================
echo RawrXD Inference Engine - Complete Build
echo ============================================================================
echo.

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

set "OBJECTS="
set "FAILED=0"

REM List of source files to compile
set "SOURCES=InferenceEngine.cpp LegacyInferenceAdapter.cpp GGMLBackend.cpp ModelLoader.cpp"
set "SOURCES=!SOURCES! GGMLTransformerLayer.cpp GGMLCompleteForward.cpp GGMLForwardPass.cpp GGMLWeightLoader.cpp"

echo Compiling source files...
echo.

for %%f in (!SOURCES!) do (
    set "SRC_FILE=%SRC_DIR%\%%f"
    set "OBJ_FILE=%BUILD_DIR%\%%~nf.o"
    set "OBJECTS=!OBJECTS! !OBJ_FILE!"
    
    if exist "!SRC_FILE!" (
        echo [Compiling] %%f
        %CXX% %CXXFLAGS% %INCLUDES% -c "!SRC_FILE!" -o "!OBJ_FILE!" 2>nul
        if errorlevel 1 (
            echo [FAILED] %%f
            set "FAILED=1"
        ) else (
            echo [OK] %%f
        )
    ) else (
        echo [MISSING] %%f
    )
)

echo.

if !FAILED! == 1 (
    echo ERROR: Some compilation failed
    exit /b 1
)

echo ============================================================================
echo Creating static library...
echo ============================================================================
echo.

set "LIB_FILE=%BIN_DIR%\libRawrXD_Inference.a"
ar rcs "!LIB_FILE!" !OBJECTS! 2>nul

if errorlevel 1 (
    echo ERROR: Failed to create library
    exit /b 1
)

echo [OK] Created !LIB_FILE!
echo.

echo ============================================================================
echo Build Summary
echo ============================================================================
echo.
echo Library: !LIB_FILE!
echo Objects: !OBJECTS!
echo.
echo Build complete!
echo.

endlocal
