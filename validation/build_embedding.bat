@echo off
:: Build script for embedding_stage validation

setlocal enabledelayedexpansion

if "%~1"=="" (
    set "CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
) else (
    set "CL_PATH=%~1"
)

echo [BUILD] Building embedding_stage.cpp...

"%CL_PATH%" /EHsc /O2 /W4 /nologo embedding_stage.cpp /Fe:embedding_stage.exe

if %ERRORLEVEL% neq 0 (
    echo [BUILD] FAILED
    exit /b 1
)

echo [BUILD] SUCCESS: embedding_stage.exe created
echo.
echo [RUN] Executing embedding validation...
echo.

embedding_stage.exe val-019/vectors/embedding_input.bin val-019/vectors/embedding_expected.bin val-019/evidence/embedding_actual.bin

endlocal
