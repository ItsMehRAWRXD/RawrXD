@echo off
REM Build Inference Correctness Harness
REM Phase 1: Bit-exact validation comparing RawrXD vs llama.cpp

echo Building Inference Correctness Harness...
echo.

set SRC=tests\inference_correctness_harness.cpp
set OUT=bin\InferenceCorrectnessHarness.exe

REM Use VS2022 compiler
set CL="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"

if not exist %CL% (
    echo ERROR: Visual Studio 2022 compiler not found
    echo Looking for: %CL%
    exit /b 1
)

REM Compile with optimizations
echo Compiling %SRC%...
%CL% /EHsc /O2 /Zi /W4 /I.\src /I.\include %SRC% /Fe%OUT% /link

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESS: %OUT%
echo.
echo Usage: %OUT% [model_path]
echo Example: %OUT% models\llama-7b.Q4_0.gguf
echo.
