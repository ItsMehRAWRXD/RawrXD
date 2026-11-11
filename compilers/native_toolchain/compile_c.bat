@echo off
setlocal enabledelayedexpansion

:: RawrXD Native C Compiler
:: Compiles .c files to .exe using working C compiler

if "%~1"=="" (
    echo Usage: compile_c.bat ^<input.c^> [output.exe]
    exit /b 1
)

set "INPUT_FILE=%~1"
set "OUTPUT_FILE=%~2"

if not defined OUTPUT_FILE (
    set "OUTPUT_FILE=%~n1.exe"
)

echo ============================================
echo RawrXD Native C Compiler
echo ============================================
echo Input:  %INPUT_FILE%
echo Output: %OUTPUT_FILE%
echo.

:: Check if input exists
if not exist "%INPUT_FILE%" (
    echo ERROR: Input file not found: %INPUT_FILE%
    exit /b 1
)

:: Get toolchain directory
set "TOOLCHAIN_DIR=%~dp0"

:: Compile
echo [1/1] Compiling %INPUT_FILE%...
"%TOOLCHAIN_DIR%c_compiler_working.exe" "%INPUT_FILE%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed with code %ERRORLEVEL%
    exit /b 1
)

:: The C compiler creates test_c.exe, rename if needed
if exist "test_c.exe" (
    if /I not "%OUTPUT_FILE%"=="test_c.exe" (
        move /Y "test_c.exe" "%OUTPUT_FILE%" >nul
    )
)

echo.
echo ============================================
echo SUCCESS: Compiled %OUTPUT_FILE%
echo ============================================

exit /b 0
