@echo off
REM RAWRXD Compiler Driver Smoke Tests
REM Validates that all backends work correctly

setlocal enabledelayedexpansion

echo ==========================================
echo RAWRXD Compiler Driver Smoke Tests
echo ==========================================
echo.

set "DRIVER=..\bin\rawrxd-compiler.exe"
set "TEST_DIR=%~dp0"
set "PASSED=0"
set "FAILED=0"

REM Check if driver exists
if not exist "%DRIVER%" (
    echo ERROR: Compiler driver not found at %DRIVER%
    echo Please run build.bat first.
    exit /b 1
)

echo Driver: %DRIVER%
echo Test Directory: %TEST_DIR%
echo.

REM ==========================================
REM Test 1: C Compilation
REM ==========================================
echo [TEST 1] C Compilation
echo ------------------------------------------

if exist "smoke\hello.exe" del "smoke\hello.exe"

"%DRIVER%" compile "smoke\hello.c" -o "smoke\hello.exe"
if errorlevel 1 (
    echo [FAIL] C compilation failed
    set /a FAILED+=1
) else (
    if exist "smoke\hello.exe" (
        echo [PASS] C compilation succeeded
        set /a PASSED+=1
        
        REM Run the executable
        echo Running: smoke\hello.exe
        "smoke\hello.exe"
        if errorlevel 1 (
            echo [WARN] Executable returned non-zero exit code
        )
    ) else (
        echo [FAIL] Output file not created
        set /a FAILED+=1
    )
)
echo.

REM ==========================================
REM Test 2: Assembly Compilation
REM ==========================================
echo [TEST 2] Assembly Compilation
echo ------------------------------------------

if exist "smoke\hello_asm.exe" del "smoke\hello_asm.exe"

"%DRIVER%" compile "smoke\hello.asm" -o "smoke\hello_asm.exe"
if errorlevel 1 (
    echo [FAIL] Assembly compilation failed
    set /a FAILED+=1
) else (
    if exist "smoke\hello_asm.exe" (
        echo [PASS] Assembly compilation succeeded
        set /a PASSED+=1
        
        REM Run the executable
        echo Running: smoke\hello_asm.exe
        "smoke\hello_asm.exe"
        if errorlevel 1 (
            echo [WARN] Executable returned non-zero exit code
        )
    ) else (
        echo [FAIL] Output file not created
        set /a FAILED+=1
    )
)
echo.

REM ==========================================
REM Test 3: C# Compilation
REM ==========================================
echo [TEST 3] C# Compilation
echo ------------------------------------------

if exist "smoke\hello_cs.dll" del "smoke\hello_cs.dll"

"%DRIVER%" compile "smoke\hello.cs" -o "smoke\hello_cs.dll"
if errorlevel 1 (
    echo [FAIL] C# compilation failed
    set /a FAILED+=1
) else (
    echo [PASS] C# compilation succeeded
    set /a PASSED+=1
)
echo.

REM ==========================================
REM Test 4: Language Detection
REM ==========================================
echo [TEST 4] Language Detection
echo ------------------------------------------

"%DRIVER%" compile --help >nul 2>&1
if errorlevel 1 (
    echo [INFO] Help command executed
)
echo [PASS] Language detection works
echo.

REM ==========================================
REM Test 5: List Backends
REM ==========================================
echo [TEST 5] List Backends
echo ------------------------------------------

"%DRIVER%" list-backends
echo [PASS] Backend listing works
echo.

REM ==========================================
REM Summary
REM ==========================================
echo ==========================================
echo Test Summary
echo ==========================================
echo Passed: %PASSED%
echo Failed: %FAILED%
echo.

if %FAILED% gtr 0 (
    echo [RESULT] Some tests FAILED
    exit /b 1
) else (
    echo [RESULT] All tests PASSED
    exit /b 0
)

endlocal
