@echo off
REM ===============================================================================
REM Silent Executable Debugger and Fixer
REM Diagnoses and fixes silent compiler executables
REM ===============================================================================

setlocal EnableDelayedExpansion

echo ===============================================================================
echo Silent Executable Debugger
echo ===============================================================================
echo.

set COMPILER_DIR=d:\rawrxd\compilers
set VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64
set DUMPBIN=%VS_TOOLS%\dumpbin.exe
set LINK=%VS_TOOLS%\link.exe
set ML64=%VS_TOOLS%\ml64.exe
set OBJ_DIR=%COMPILER_DIR%\obj_debug
set LOG_DIR=%COMPILER_DIR%\debug_logs

REM Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Tools:
echo   DUMPBIN: %DUMPBIN%
echo   LINK: %LINK%
echo   ML64: %ML64%
echo   Logs: %LOG_DIR%
echo.

REM Check tools exist
if not exist "%DUMPBIN%" (
    echo ERROR: dumpbin.exe not found. Install VS2022 Enterprise.
    exit /b 1
)

REM ===============================================================================
REM Function: Analyze Executable
REM ===============================================================================
:AnalyzeExecutable
set EXE_NAME=%~1
set EXE_PATH=%COMPILER_DIR%\%EXE_NAME%

echo.
echo ===============================================================================
echo Analyzing: %EXE_NAME%
echo ===============================================================================

if not exist "%EXE_PATH%" (
    echo [SKIP] %EXE_NAME% not found
    goto :eof
)

echo [INFO] File exists: %EXE_PATH%
for %%F in ("%EXE_PATH%") do (
    echo [INFO] Size: %%~zF bytes
    echo [INFO] Modified: %%~tF
)

echo.
echo --- Checking PE Headers ---
"%DUMPBIN%" /headers "%EXE_PATH%" > "%LOG_DIR%\%EXE_NAME%_headers.txt" 2>&1

REM Extract subsystem
echo [INFO] Subsystem:
findstr /C:"subsystem" "%LOG_DIR%\%EXE_NAME%_headers.txt" | findstr /V "file type"

REM Extract entry point
echo [INFO] Entry Point:
findstr /C:"entry point" "%LOG_DIR%\%EXE_NAME%_headers.txt"

REM Extract machine type
echo [INFO] Machine:
findstr /C:"8664" "%LOG_DIR%\%EXE_NAME%_headers.txt" | findstr /C:"machine"

echo.
echo --- Checking Imports ---
"%DUMPBIN%" /imports "%EXE_PATH%" > "%LOG_DIR%\%EXE_NAME%_imports.txt" 2>&1

REM Check for key imports
findstr /C:"KERNEL32.dll" "%LOG_DIR%\%EXE_NAME%_imports.txt" > nul && echo [INFO] Imports KERNEL32.dll
findstr /C:"USER32.dll" "%LOG_DIR%\%EXE_NAME%_imports.txt" > nul && echo [INFO] Imports USER32.dll
findstr /C:"msvcrt" "%LOG_DIR%\%EXE_NAME%_imports.txt" > nul && echo [INFO] Imports MSVCRT

echo.
echo --- Testing Execution ---
echo [TEST] Running without arguments...
echo %TIME% > "%LOG_DIR%\%EXE_NAME%_test1.txt"
"%EXE_PATH%" >> "%LOG_DIR%\%EXE_NAME%_test1.txt" 2>&1
echo Exit code: %ERRORLEVEL% >> "%LOG_DIR%\%EXE_NAME%_test1.txt"
echo %TIME% >> "%LOG_DIR%\%EXE_NAME%_test1.txt"

REM Check if output file has content
for %%F in ("%LOG_DIR%\%EXE_NAME%_test1.txt") do set SIZE=%%~zF
if %SIZE% gtr 30 (
    echo [RESULT] Produced output (%SIZE% bytes)
) else (
    echo [RESULT] No output (likely GUI or requires input)
)

echo.
echo [TEST] Running with --help...
echo %TIME% > "%LOG_DIR%\%EXE_NAME%_test2.txt"
"%EXE_PATH%" --help >> "%LOG_DIR%\%EXE_NAME%_test2.txt" 2>&1
echo Exit code: %ERRORLEVEL% >> "%LOG_DIR%\%EXE_NAME%_test2.txt"
for %%F in ("%LOG_DIR%\%EXE_NAME%_test2.txt") do set SIZE=%%~zF
if %SIZE% gtr 30 (
    echo [RESULT] Produced output (%SIZE% bytes)
) else (
    echo [RESULT] No output
)

echo.
echo [TEST] Running with /? ...
echo %TIME% > "%LOG_DIR%\%EXE_NAME%_test3.txt"
"%EXE_PATH%" /? >> "%LOG_DIR%\%EXE_NAME%_test3.txt" 2>&1
for %%F in ("%LOG_DIR%\%EXE_NAME%_test3.txt") do set SIZE=%%~zF
if %SIZE% gtr 30 (
    echo [RESULT] Produced output (%SIZE% bytes)
) else (
    echo [RESULT] No output
)

echo.
echo --- Analysis Complete ---
echo Log files saved to: %LOG_DIR%\%EXE_NAME%_*.txt
goto :eof

REM ===============================================================================
REM Main: Analyze All Executables
REM ===============================================================================

call :AnalyzeExecutable "eon_bootstrap_compiler.exe"
call :AnalyzeExecutable "bash_compiler_from_scratch.exe"
call :AnalyzeExecutable "powershell_compiler_from_scratch.exe"
call :AnalyzeExecutable "universal_compiler_runtime.exe"
call :AnalyzeExecutable "universal_cross_platform_compiler.exe"
call :AnalyzeExecutable "omega_pro_v3.exe"
call :AnalyzeExecutable "omega_pro.exe"
call :AnalyzeExecutable "OmegaPro_v3_fixed.exe"

echo.
echo ===============================================================================
echo Analysis Complete
echo ===============================================================================
echo.
echo Review logs in: %LOG_DIR%
echo.
echo Next steps:
echo   1. Check *_headers.txt for subsystem (WINDOWS_GUI vs CONSOLE)
echo   2. Check *_imports.txt for missing dependencies
echo   3. Check *_test*.txt for any output produced
echo.
pause
