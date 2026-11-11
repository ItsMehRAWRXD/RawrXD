@echo off
REM RAWRXD Compiler Driver Smoke Tests
REM Validates that all backends work correctly

setlocal enabledelayedexpansion

set "DRIVER=..\bin\rawrxd-compiler.exe"
set "TEST_DIR=%~dp0"
set "TEMP_DIR=%TEMP%\rawrxd_test_%RANDOM%"

set "PASSED=0"
set "FAILED=0"

echo ==========================================
echo RAWRXD Compiler Driver Smoke Tests
echo ==========================================
echo.

REM Create temp directory
mkdir "%TEMP_DIR%" 2>nul

REM Check if driver exists
if not exist "%DRIVER%" (
    echo ERROR: Compiler driver not found at %DRIVER%
    echo Please run build.bat first
    exit /b 1
)

echo [INFO] Using driver: %DRIVER%
echo [INFO] Test directory: %TEMP_DIR%
echo.

REM ==========================================
REM Test 1: C Compilation
REM ==========================================
echo Test 1: C Compilation
echo --------------------

(
echo #include ^<stdio.h^>
echo int main^(^) {
echo     printf^("Hello from C!\n"^);
echo     return 0;
echo }
) > "%TEMP_DIR%\test_c.c"

"%DRIVER%" compile "%TEMP_DIR%\test_c.c" -o "%TEMP_DIR%\test_c.exe" > "%TEMP_DIR%\c_output.txt" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% equ 0 (
    if exist "%TEMP_DIR%\test_c.exe" (
        echo [PASS] C compilation succeeded
        set /a PASSED+=1
    ) else (
        echo [FAIL] C compilation succeeded but no output file
        set /a FAILED+=1
    )
) else (
    echo [FAIL] C compilation failed with exit code %EXIT_CODE%
    type "%TEMP_DIR%\c_output.txt"
    set /a FAILED+=1
)
echo.

REM ==========================================
REM Test 2: Assembly Compilation
REM ==========================================
echo Test 2: Assembly Compilation
echo ------------------------------

(
echo .code
echo main proc
echo     mov rax, 42
echo     ret
echo main endp
echo end
) > "%TEMP_DIR%\test_asm.asm"

"%DRIVER%" compile "%TEMP_DIR%\test_asm.asm" -o "%TEMP_DIR%\test_asm.exe" > "%TEMP_DIR%\asm_output.txt" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% equ 0 (
    if exist "%TEMP_DIR%\test_asm.exe" (
        echo [PASS] Assembly compilation succeeded
        set /a PASSED+=1
    ) else (
        echo [FAIL] Assembly compilation succeeded but no output file
        set /a FAILED+=1
    )
) else (
    echo [FAIL] Assembly compilation failed with exit code %EXIT_CODE%
    type "%TEMP_DIR%\asm_output.txt"
    set /a FAILED+=1
)
echo.

REM ==========================================
REM Test 3: C# Compilation
REM ==========================================
echo Test 3: C# Compilation
echo ----------------------

(
echo using System;
echo class Program {
echo     static void Main^(^) {
echo         Console.WriteLine^("Hello from C#!"^);
echo     }
echo }
) > "%TEMP_DIR%\test_cs.cs"

"%DRIVER%" compile "%TEMP_DIR%\test_cs.cs" -o "%TEMP_DIR%\test_cs.dll" > "%TEMP_DIR%\cs_output.txt" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% equ 0 (
    echo [PASS] C# compilation succeeded
    set /a PASSED+=1
) else (
    echo [FAIL] C# compilation failed with exit code %EXIT_CODE%
    type "%TEMP_DIR%\cs_output.txt"
    set /a FAILED+=1
)
echo.

REM ==========================================
REM Test 4: Language Detection
REM ==========================================
echo Test 4: Language Detection
echo --------------------------

"%DRIVER%" compile "%TEMP_DIR%\test_c.c" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] Auto-detected C file
    set /a PASSED+=1
) else (
    echo [FAIL] Failed to auto-detect C file
    set /a FAILED+=1
)

echo.

REM ==========================================
REM Test 5: List Backends
REM ==========================================
echo Test 5: List Backends
echo ---------------------

"%DRIVER%" list-backends > "%TEMP_DIR%\backends.txt" 2>&1
findstr /C:"rawrxd-c" "%TEMP_DIR%\backends.txt" >nul
if %ERRORLEVEL% equ 0 (
    echo [PASS] C backend registered
    set /a PASSED+=1
) else (
    echo [FAIL] C backend not found
    set /a FAILED+=1
)

findstr /C:"rawrxd-asm" "%TEMP_DIR%\backends.txt" >nul
if %ERRORLEVEL% equ 0 (
    echo [PASS] ASM backend registered
    set /a PASSED+=1
) else (
    echo [FAIL] ASM backend not found
    set /a FAILED+=1
)

findstr /C:"rawrxd-csharp" "%TEMP_DIR%\backends.txt" >nul
if %ERRORLEVEL% equ 0 (
    echo [PASS] C# backend registered
    set /a PASSED+=1
) else (
    echo [FAIL] C# backend not found
    set /a FAILED+=1
)

echo.

REM ==========================================
REM Test 6: Error Handling
REM ==========================================
echo Test 6: Error Handling
echo ---------------------

REM Test with non-existent file
"%DRIVER%" compile "%TEMP_DIR%\nonexistent.c" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [PASS] Correctly failed on non-existent file
    set /a PASSED+=1
) else (
    echo [FAIL] Should have failed on non-existent file
    set /a FAILED+=1
)

REM Test with unknown extension
echo "test" > "%TEMP_DIR%\test.unknown"
"%DRIVER%" compile "%TEMP_DIR%\test.unknown" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [PASS] Correctly failed on unknown extension
    set /a PASSED+=1
) else (
    echo [FAIL] Should have failed on unknown extension
    set /a FAILED+=1
)

echo.

REM ==========================================
REM Summary
REM ==========================================
echo ==========================================
echo Test Summary
echo ==========================================
echo Passed: %PASSED%
echo Failed: %FAILED%
echo Total:  %PASSED% + %FAILED%
echo.

REM Cleanup
rmdir /S /Q "%TEMP_DIR%" 2>nul

if %FAILED% equ 0 (
    echo [SUCCESS] All tests passed!
    exit /b 0
) else (
    echo [FAILURE] Some tests failed
    exit /b 1
)
