@echo off
setlocal EnableDelayedExpansion

:: RawrXD-Script Test Report Generator
:: Produces detailed markdown report with execution results

echo ============================================
echo RawrXD-Script Test Report Generator
echo ============================================
echo.

set "RAWRXD_EXE=d:\rawrxd\build\RawrXD_Script.exe"
set "NODE_EXE=node"
set "TEST_ROOT=d:\rawrxd\src\script\tests"
set "REPORT_FILE=%TEST_ROOT%\results\test_report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.md"

:: Create results directory
if not exist "%TEST_ROOT%\results" mkdir "%TEST_ROOT%\results"

set /a TOTAL=0
set /a PASSED=0
set /a FAILED=0

:: Start report generation
echo Generating test report...
echo.

(
echo # RawrXD-Script Validation Test Report
echo.
echo **Generated:** %date% %time%
echo **Engine:** RawrXD-Script x64 MASM
echo **Reference:** Node.js LTS
echo.
echo ---
echo.
echo ## Executive Summary
echo.
echo | Metric | Value |
echo |--------|-------|
) > "%REPORT_FILE%"

:: ============================================
:: DIFFERENTIAL TESTS
:: ============================================
(
echo.
echo ## Differential Tests
echo.
echo Tests comparing RawrXD output against Node.js reference implementation.
echo.
echo | Category | Test | Status | Details |
echo |----------|------|--------|---------|
) >> "%REPORT_FILE%"

for /d %%C in ("%TEST_ROOT%\differential\corpus\*") do (
    set "CATEGORY=%%~nxC"
    
    for %%T in ("%%C\*.js") do (
        set /a TOTAL+=1
        set "TEST_NAME=%%~nT"
        
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
                echo | set /p="| !CATEGORY! | !TEST_NAME! | PASS | Output matches Node.js |" >> "%REPORT_FILE%"
                echo. >> "%REPORT_FILE%"
                set /a PASSED+=1
            ) else (
                echo | set /p="| !CATEGORY! | !TEST_NAME! | FAIL | Exit code mismatch: RawrXD=!RAWRXD_EXIT!, Node=!NODE_EXIT! |" >> "%REPORT_FILE%"
                echo. >> "%REPORT_FILE%"
                set /a FAILED+=1
            )
        ) else (
            echo | set /p="| !CATEGORY! | !TEST_NAME! | FAIL | Output mismatch |" >> "%REPORT_FILE%"
            echo. >> "%REPORT_FILE%"
            set /a FAILED+=1
        )
    )
)

:: ============================================
:: REGRESSION TESTS
:: ============================================
(
echo.
echo ## Regression Tests
echo.
echo Tests verifying fixes for previously reported bugs.
echo.
echo | Test | Status | Details |
echo |------|--------|---------|
) >> "%REPORT_FILE%"

for %%T in ("%TEST_ROOT%\regression\*.js") do (
    set /a TOTAL+=1
    set "TEST_NAME=%%~nT"
    
    :: Run with RawrXD
    "!RAWRXD_EXE!" "%%T" > "%TEMP%\rawrxd_out.txt" 2>"%TEMP%\rawrxd_err.txt"
    set "RAWRXD_EXIT=!ERRORLEVEL!"
    
    if !RAWRXD_EXIT! equ 0 (
        echo | set /p="| !TEST_NAME! | PASS | Clean execution |" >> "%REPORT_FILE%"
        echo. >> "%REPORT_FILE%"
        set /a PASSED+=1
    ) else (
        echo | set /p="| !TEST_NAME! | FAIL | Exit code: !RAWRXD_EXIT! |" >> "%REPORT_FILE%"
        echo. >> "%REPORT_FILE%"
        set /a FAILED+=1
    )
)

:: ============================================
:: SUMMARY
:: ============================================
set /a PASS_RATE=(PASSED*100)/TOTAL

(
echo.
echo ## Summary
echo.
echo | Metric | Count |
echo |--------|-------|
echo | **Total Tests** | %TOTAL% |
echo | **Passed** | %PASSED% |
echo | **Failed** | %FAILED% |
echo | **Pass Rate** | %PASS_RATE%%% |
echo.
echo ---
echo.
echo ## Test Categories
echo.
echo - **Differential Tests:** Cross-engine validation against Node.js
echo - **Regression Tests:** Bug fix verification
echo.
echo ## Notes
echo.
echo - All differential tests compare stdout output byte-for-byte
echo - Exit codes must match between engines for PASS status
echo - Regression tests verify clean execution (exit code 0)
echo.
) >> "%REPORT_FILE%"

:: Display summary
echo ============================================
echo TEST REPORT GENERATED
echo ============================================
echo.
echo Total Tests:  %TOTAL%
echo Passed:       %PASSED%
echo Failed:       %FAILED%
echo Pass Rate:    %PASS_RATE%%%
echo.
echo Report saved to:
echo %REPORT_FILE%
echo.

:: Display report
type "%REPORT_FILE%"

exit /b 0
