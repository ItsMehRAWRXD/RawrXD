@echo off
REM Truth Gate 003 Build Script
REM Builds the end-to-end integration test

setlocal enabledelayedexpansion

echo ============================================
echo Truth Gate 003: Runtime Integration Build
echo ============================================
echo.

set SRC_DIR=src\truth_gate
set OBJ_DIR=obj\truth_gate
set BIN_DIR=bin

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

REM Compiler flags
set CFLAGS=-std=c++17 -O2 -Wall -Wextra
set INCLUDES=-I src\runtime -I src\fabric -I src\truth_gate
set DEFINES=-DTRUTH_GATE_003_BUILD -D_CRT_SECURE_NO_WARNINGS

REM Source files
set SOURCES=%SRC_DIR%\truth_gate_003_main.cpp^
          %SRC_DIR%\gguf_integration.cpp^
          %SRC_DIR%\fabric_integration.cpp^
          %SRC_DIR%\transformer_executor.cpp^
          %SRC_DIR%\tokenizer_integration.cpp^
          %SRC_DIR%\sampler_integration.cpp^
          %SRC_DIR%\llamacpp_validator.cpp

REM Object files
set OBJS=%OBJ_DIR%\truth_gate_003_main.obj^
       %OBJ_DIR%\gguf_integration.obj^
       %OBJ_DIR%\fabric_integration.obj^
       %OBJ_DIR%\transformer_executor.obj^
       %OBJ_DIR%\tokenizer_integration.obj^
       %OBJ_DIR%\sampler_integration.obj^
       %OBJ_DIR%\llamacpp_validator.obj

echo Compiling Truth Gate 003...
echo.

REM Compile each source file
for %%f in (%SOURCES%) do (
    echo Compiling %%f...
    g++ %CFLAGS% %INCLUDES% %DEFINES% -c %%f -o %OBJ_DIR%\%%~nf.obj
    if !errorlevel! neq 0 (
        echo FAILED to compile %%f
        exit /b 1
    )
)

echo.
echo Linking...

REM Link executable
g++ -o %BIN_DIR%\truth_gate_003.exe %OBJS%^
    -L. -lsovereign_runtime -lrawramxd_fabric^
    -lpthread

if %errorlevel% neq 0 (
    echo FAILED to link
    exit /b 1
)

echo.
echo ============================================
echo Build SUCCESSFUL
echo Output: %BIN_DIR%\truth_gate_003.exe
echo ============================================

REM Run the test
echo.
echo Running Truth Gate 003...
echo.
%BIN_DIR%\truth_gate_003.exe

endlocal
