@echo off
setlocal enabledelayedexpansion

:: RawrXD Native Assembly Compiler
:: Assembles .asm files to .exe using native toolchain

if "%~1"=="" (
    echo Usage: compile_asm.bat ^<input.asm^> [output.exe]
    exit /b 1
)

set "INPUT_FILE=%~1"
set "OUTPUT_FILE=%~2"

if not defined OUTPUT_FILE (
    set "OUTPUT_FILE=%~n1.exe"
)

set "OBJ_FILE=%TEMP%\%~n1_rawrxd.obj"

echo ============================================
echo RawrXD Native Assembly Compiler
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

:: Assemble
echo [1/2] Assembling %INPUT_FILE%...
"%TOOLCHAIN_DIR%rawrxd_native_assembler.exe" "%INPUT_FILE%" "%OBJ_FILE%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Assembly failed with code %ERRORLEVEL%
    if exist "%OBJ_FILE%" del "%OBJ_FILE%"
    exit /b 1
)
echo       Assembled: %OBJ_FILE%

:: Link
echo [2/2] Linking %OBJ_FILE%...
"%TOOLCHAIN_DIR%rawrxd_native_linker_v2.exe" "%OBJ_FILE%" /out:"%OUTPUT_FILE%" /subsystem:3
if %ERRORLEVEL% neq 0 (
    echo ERROR: Linking failed with code %ERRORLEVEL%
    if exist "%OBJ_FILE%" del "%OBJ_FILE%"
    exit /b 1
)
echo       Linked: %OUTPUT_FILE%

:: Cleanup
if exist "%OBJ_FILE%" del "%OBJ_FILE%"

echo.
echo ============================================
echo SUCCESS: Compiled %OUTPUT_FILE%
echo ============================================

exit /b 0
