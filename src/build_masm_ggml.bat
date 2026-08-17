@echo off
REM Build script for Pure MASM GGML Implementation
REM No external dependencies - completely self-contained

setlocal EnableDelayedExpansion

echo ========================================
echo Building Pure MASM GGML Implementation
echo ========================================

REM Set paths
set SRC_DIR=%~dp0
set OBJ_DIR=%SRC_DIR%\obj\masm
set BIN_DIR=%SRC_DIR%\bin
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set CL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

REM Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo.
echo Step 1: Assembling MASM core operations...
echo ----------------------------------------

REM Assemble the core operations
%ML64% /c /W3 /nologo /Zi /Fo "%OBJ_DIR%\ggml_core_ops.obj" "%SRC_DIR%\ggml_masm\ggml_core_ops.asm"
if errorlevel 1 (
    echo ERROR: Failed to assemble ggml_core_ops.asm
    exit /b 1
)
echo [OK] ggml_core_ops.asm

echo.
echo Step 2: Compiling C wrapper...
echo ----------------------------------------

REM Compile the C wrapper
%CL% /c /W4 /nologo /O2 /Zi /MD /EHsc /Fo "%OBJ_DIR%\ggml_masm_pure.obj" /I "%SRC_DIR%" "%SRC_DIR%\ggml_masm\ggml_masm_pure.c"
if errorlevel 1 (
    echo ERROR: Failed to compile ggml_masm_pure.c
    exit /b 1
)
echo [OK] ggml_masm_pure.c

echo.
echo Step 3: Compiling inference engine...
echo ----------------------------------------

REM Compile inference engine
%CL% /c /W4 /nologo /O2 /Zi /MD /EHsc /Fo "%OBJ_DIR%\inference_engine_masm.obj" /I "%SRC_DIR%" "%SRC_DIR%\inference\inference_engine_masm.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile inference_engine_masm.cpp
    exit /b 1
)
echo [OK] inference_engine_masm.cpp

echo.
echo Step 4: Compiling AI model caller...
echo ----------------------------------------

REM Compile AI model caller
%CL% /c /W4 /nologo /O2 /Zi /MD /EHsc /Fo "%OBJ_DIR%\ai_model_caller_masm.obj" /I "%SRC_DIR%" "%SRC_DIR%\ai\ai_model_caller_masm.cpp"
if errorlevel 1 (
    echo ERROR: Failed to compile ai_model_caller_masm.cpp
    exit /b 1
)
echo [OK] ai_model_caller_masm.cpp

echo.
echo Step 5: Creating static library...
echo ----------------------------------------

REM Create static library
set LIB_EXE="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"
%LIB_EXE% /nologo /OUT:"%BIN_DIR%\ggml_masm.lib" ^
    "%OBJ_DIR%\ggml_core_ops.obj" ^
    "%OBJ_DIR%\ggml_masm_pure.obj" ^
    "%OBJ_DIR%\inference_engine_masm.obj" ^
    "%OBJ_DIR%\ai_model_caller_masm.obj"
if errorlevel 1 (
    echo ERROR: Failed to create library
    exit /b 1
)
echo [OK] Created ggml_masm.lib

echo.
echo Step 6: Building test executable...
echo ----------------------------------------

REM Compile test
%CL% /W4 /nologo /O2 /Zi /MD /EHsc /Fe "%BIN_DIR%\test_masm_ggml.exe" ^
    /I "%SRC_DIR%" ^
    "%SRC_DIR%\ggml_masm\test_masm_ops.cpp" ^
    "%BIN_DIR%\ggml_masm.lib"
if errorlevel 1 (
    echo ERROR: Failed to build test executable
    exit /b 1
)
echo [OK] Created test_masm_ggml.exe

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo Output files:
echo   Library: %BIN_DIR%\ggml_masm.lib
echo   Test:    %BIN_DIR%\test_masm_ggml.exe
echo.
echo To run tests: %BIN_DIR%\test_masm_ggml.exe
echo.

endlocal
