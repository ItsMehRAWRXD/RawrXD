@echo off
setlocal EnableDelayedExpansion

:: RawrXD-Script Validation Test Runner
:: Generates actual test execution results

echo ============================================
echo RawrXD-Script Validation Test Suite
echo ============================================
echo.

set "RAWRXD_EXE=d:\rawrxd\build\RawrXD_Script.exe"
set "NODE_EXE=node"
set "TEST_ROOT=d:\rawrxd\src\script\tests"
set "RESULTS_FILE=%TEST_ROOT%\results\test_results_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt"

:: Create results directory
if not exist "%TEST_ROOT%\results" mkdir "%TEST_ROOT%\results"

set /a TOTAL=0
set /a PASSED=0
set /a FAILED=0
set /a SKIPPED=0

echo Test Execution Started: %date% %time%
echo.

:: ============================================
:: DIFFERENTIAL TESTS
:: ============================================
echo [DIFFERENTIAL TESTS]
echo.

for /d %%C in ("%TEST_ROOT%\differential\corpus\*") do (
    set "CATEGORY=%%~nxC"
    echo   Category: !CATEGORY!
    
    for %%T in ("%%C\*.js") do (
        set /a TOTAL+=1
        set "TEST_NAME=%%~nxT"
        
        :: Run with RawrXD
        "!RAWRXD_EXE!" "%%T" > "%TEMP%\rawrxd_out.txt" 2>"%TEMP%\rawrxd_err.txt"
        set "RAWRXD_EXIT=!ERRORLEVEL!"
        
        :: Run with Node.js
        "!NODE_EXE!" "%%T" > "%TEMP%\node_out.txt" 2>"%TEMP%\node_err.txt"
        set "NODE_EXIT=!ERRORLEVEL!"
        
        :: Compare outputs
        fc /b "%TEMP%\rawrxd_out.txt" "%TEMP%\node_out.txt" > nul 2>&1
        if !ERRORLEVEL! equ 0 (
            if !RAWRXD_EXIT! equ !NODE_EXIT! (
                echo     [PASS] !TEST_NAME!
                set /a PASSED+=1
            ) else (
                echo     [FAIL] !TEST_NAME! - Exit code mismatch
                echo       RawrXD: !RAWRXD_EXIT!, Node: !NODE_EXIT!
                set /a FAILED+=1
            )
        ) else (
            echo     [FAIL] !TEST_NAME! - Output mismatch
            echo       Expected:
            type "%TEMP%\node_out.txt" | findstr /n "^" | head -5
            echo       Got:
            type "%TEMP%\rawrxd_out.txt" | findstr /n "^" | head -5
            set /a FAILED+=1
        )
    )
)

echo.

:: ============================================
:: REGRESSION TESTS
:: ============================================
echo [REGRESSION TESTS]
echo.

for %%T in ("%TEST_ROOT%\regression\*.js") do (
    set /a TOTAL+=1
    set "TEST_NAME=%%~nxT"
    
    :: Run with RawrXD
    "!RAWRXD_EXE!" "%%T" > "%TEMP%\rawrxd_out.txt" 2>"%TEMP%\rawrxd_err.txt"
    set "RAWRXD_EXIT=!ERRORLEVEL!"
    
    if !RAWRXD_EXIT! equ 0 (
        echo     [PASS] !TEST_NAME!
        set /a PASSED+=1
    ) else (
        echo     [FAIL] !TEST_NAME! - Exit code: !RAWRXD_EXIT!
        if exist "%TEMP%\rawrxd_err.txt" (
            type "%TEMP%\rawrxd_err.txt" | head -3
        )
        set /a FAILED+=1
    )
)

echo.

:: ============================================
:: SUMMARY
:: ============================================
echo ============================================
echo TEST RESULTS SUMMARY
echo ============================================
echo Total Tests:  %TOTAL%
echo Passed:       %PASSED%
echo Failed:       %FAILED%
echo Skipped:      %SKIPPED%
echo.
set /a PASS_RATE=(PASSED*100)/TOTAL
if %TOTAL% gtr 0 (
    echo Pass Rate:    %PASS_RATE%%%
) else (
    echo Pass Rate:    N/A
)
echo.
echo Test Execution Completed: %date% %time%
echo.

:: Save results to file
(
echo RawrXD-Script Validation Test Results
echo ============================================
echo Date: %date% %time%
echo.
echo Total Tests: %TOTAL%
echo Passed: %PASSED%
echo Failed: %FAILED%
echo Skipped: %SKIPPED%
echo Pass Rate: %PASS_RATE%%%
) > "%RESULTS_FILE%"

echo Results saved to: %RESULTS_FILE%

:: Exit with appropriate code
if %FAILED% gtr 0 (
    exit /b 1
) else (
    exit /b 0
)
