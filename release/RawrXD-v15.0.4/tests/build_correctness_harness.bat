@echo off
REM Build Inference Correctness Harness
REM Phase 1: Bit-exact validation comparing RawrXD vs llama.cpp

echo Building Inference Correctness Harness...
echo.

set SRC=inference_correctness_harness.cpp
set OUT=..\bin\InferenceCorrectnessHarness.exe

REM Setup VS2022 environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to setup VS2022 environment
    exit /b 1
)

REM Compile with optimizations
echo Compiling %SRC%...
cl /EHsc /O2 /Zi /W4 /I..\src /I..\include %SRC% /Fe%OUT%

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
