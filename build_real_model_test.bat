@echo off
REM Build the real model loader test

echo ==========================================
echo Building Real Model Loader Test
echo ==========================================
echo.

set SOURCE=d:\rawrxd\tests\test_real_model_loader.cpp
set OUTPUT=d:\rawrxd\build\test_real_model_loader.exe

if not exist d:\rawrxd\build mkdir d:\rawrxd\build

REM Use GCC compiler
g++.exe -std=c++17 -O2 -Wall -o %OUTPUT% %SOURCE%

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL: %OUTPUT%
echo.

REM Check for GGUF files
set "FOUND_GGUF=""
for /r "F:\" %%i in (*.gguf) do (
    if "!FOUND_GGUF!"=="" (
        set "FOUND_GGUF=%%i"
        echo Found GGUF file: %%i
    )
)

if "!FOUND_GGUF!"=="" (
    echo.
    echo No GGUF files found. Please provide a path to a GGUF file.
    echo Usage: %OUTPUT% ^<path_to_gguf_file^>
    exit /b 0
)

echo.
echo Running test with found GGUF file...
echo.
%OUTPUT% "%FOUND_GGUF%"

exit /b %ERRORLEVEL%
