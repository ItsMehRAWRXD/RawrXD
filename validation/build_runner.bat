@echo off
:: Build script for validation_runner
:: Usage: build_runner.bat [path_to_cl.exe]

setlocal enabledelayedexpansion

if "%~1"=="" (
    set "CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
) else (
    set "CL_PATH=%~1"
)

echo [BUILD] Using compiler: %CL_PATH%
echo [BUILD] Building val_runner.cpp...

"%CL_PATH%" /EHsc /O2 /W4 /nologo val_runner.cpp /Fe:val_runner.exe

if %ERRORLEVEL% neq 0 (
    echo [BUILD] FAILED
    exit /b 1
)

echo [BUILD] SUCCESS: val_runner.exe created
echo [BUILD] Run with: val_runner.exe [metadata.json] [report.json]

endlocal
