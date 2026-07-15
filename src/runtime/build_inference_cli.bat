@echo off
REM Build script for Inference CLI (Complete Pipeline C1-C4)

echo ========================================
echo Building RawrXD Inference CLI
echo ========================================

set CXX=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set INCLUDES=-I. -I.. -I../..
set FLAGS=-std=c++17 -O2 -mavx2 -mfma -Wall

echo Compiling inference_cli.cpp...
%CXX% %FLAGS% %INCLUDES% -c inference_cli.cpp -o inference_cli.obj
if errorlevel 1 (
    echo FAILED: inference_cli.cpp
    exit /b 1
)

echo Linking executable...
%CXX% %FLAGS% -o inference_cli.exe inference_cli.obj inference_engine.obj embedding_lookup.obj tokenizer_runtime.obj ..\model\model_context.obj
if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ========================================
echo Build successful!
echo ========================================
echo.
echo Usage: inference_cli.exe -m model.gguf -p "prompt"
echo.
