@echo off
setlocal EnableDelayedExpansion

:: RawrXD-Script Enhanced Test Runner
:: Produces actionable debug output for failures

echo ============================================
echo RawrXD-Script Validation Test Suite
echo ============================================
echo.

set "RAWRXD_EXE=d:\rawrxd\build\bin\RawrXD_Script.exe"
set "RAWRXD_DBG=d:\rawrxd\build\bin\RawrXD_Script_Debug.exe"
set "NODE_EXE=node"
set "TEST_ROOT=d:\rawrxd\src\script\tests"
set "RESULTS_FILE=%TEST_ROOT%\results\test_results_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.md"

:: Create results directory
if not exist "%TEST_ROOT%\results" mkdir "%TEST_ROOT%\results"

set /a TOTAL=0
set /a PASSED=0
set /a FAILED=0

echo Test Execution Started: %date% %time%
echo.

:: Start markdown report
echo # RawrXD-Script Test Execution Report > "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo **Date:** %date% %time% >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo --- >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: ============================================
:: DIFFERENTIAL TESTS
:: ============================================
echo ## Differential Tests >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

for /d %%C in ("%TEST_ROOT%\differential\corpus\*") do (
    set "CATEGORY=%%~nxC"
    echo ### Category: !CATEGORY! >> "%RESULTS_FILE%"
    echo. >> "%RESULTS_FILE%"
    echo   [!CATEGORY!]
    
    for %%T in ("%%C\*.js") do (
        set /a TOTAL+=1
        set "TEST_NAME=%%~nxT"
        set "TEST_PATH=%%T"
        
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
                echo #### !TEST_NAME! - PASS >> "%RESULTS_FILE%"
                echo. >> "%RESULTS_FILE%"
                set /a PASSED+=1
            ) else (
                echo     [FAIL] !TEST_NAME! - Exit code mismatch
                call :ReportFailure "!TEST_NAME!" "!TEST_PATH!" "Exit code mismatch: RawrXD=!RAWRXD_EXIT!, Node=!NODE_EXIT!"
                set /a FAILED+=1
            )
        ) else (
            echo     [FAIL] !TEST_NAME! - Output mismatch
            call :ReportFailure "!TEST_NAME!" "!TEST_PATH!" "Output mismatch"
            set /a FAILED+=1
        )
    )
    echo. >> "%RESULTS_FILE%"
)

echo.

:: ============================================
:: REGRESSION TESTS
:: ============================================
echo ## Regression Tests >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo   [REGRESSION]

for %%T in ("%TEST_ROOT%\regression\*.js") do (
    set /a TOTAL+=1
    set "TEST_NAME=%%~nxT"
    set "TEST_PATH=%%T"
    
    :: Run with RawrXD
    "!RAWRXD_EXE!" "%%T" > "%TEMP%\rawrxd_out.txt" 2>"%TEMP%\rawrxd_err.txt"
    set "RAWRXD_EXIT=!ERRORLEVEL!"
    
    if !RAWRXD_EXIT! equ 0 (
        echo     [PASS] !TEST_NAME!
        echo #### !TEST_NAME! - PASS >> "%RESULTS_FILE%"
        echo. >> "%RESULTS_FILE%"
        set /a PASSED+=1
    ) else (
        echo     [FAIL] !TEST_NAME! - Exit code: !RAWRXD_EXIT!
        call :ReportFailure "!TEST_NAME!" "!TEST_PATH!" "Exit code: !RAWRXD_EXIT!"
        set /a FAILED+=1
    )
)

echo. >> "%RESULTS_FILE%"

:: ============================================
:: SUMMARY
:: ============================================
echo ## Summary >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo | Metric | Value | >> "%RESULTS_FILE%"
echo |--------|-------| >> "%RESULTS_FILE%"
echo | Total Tests | %TOTAL% | >> "%RESULTS_FILE%"
echo | Passed | %PASSED% | >> "%RESULTS_FILE%"
echo | Failed | %FAILED% | >> "%RESULTS_FILE%"

set /a PASS_RATE=0
if %TOTAL% gtr 0 (
    set /a PASS_RATE=(PASSED*100)/TOTAL
)
echo | Pass Rate | %PASS_RATE%%% | >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Console summary
echo ============================================
echo TEST RESULTS SUMMARY
echo ============================================
echo Total Tests:  %TOTAL%
echo Passed:       %PASSED%
echo Failed:       %FAILED%
echo Pass Rate:    %PASS_RATE%%%
echo.
echo Report saved to: %RESULTS_FILE%
echo.

if %FAILED% gtr 0 (
    exit /b 1
) else (
    exit /b 0
)

:: ============================================
:: FAILURE REPORTING SUBROUTINE
:: ============================================
:ReportFailure
set "FAIL_NAME=%~1"
set "FAIL_PATH=%~2"
set "FAIL_REASON=%~3"

echo #### %FAIL_NAME% - FAIL >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo **Reason:** %FAIL_REASON% >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Show source
echo **Source:** >> "%RESULTS_FILE%"
echo ```javascript >> "%RESULTS_FILE%"
type "%FAIL_PATH%" >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Show expected output
echo **Expected (Node.js):** >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
type "%TEMP%\node_out.txt" >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Show actual output
echo **Actual (RawrXD):** >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
type "%TEMP%\rawrxd_out.txt" >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Show stderr if any
echo **Stderr (RawrXD):** >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
type "%TEMP%\rawrxd_err.txt" >> "%RESULTS_FILE%"
echo ``` >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

:: Try to get bytecode dump if debug build exists
if exist "%RAWRXD_DBG%" (
    echo **Bytecode Dump:** >> "%RESULTS_FILE%"
    echo ``` >> "%RESULTS_FILE%"
    "%RAWRXD_DBG%" --dump-bytecode "%FAIL_PATH%" 2>> "%RESULTS_FILE%"
    echo ``` >> "%RESULTS_FILE%"
    echo. >> "%RESULTS_FILE%"
)

echo **Reference:** Node.js LTS >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"
echo --- >> "%RESULTS_FILE%"
echo. >> "%RESULTS_FILE%"

goto :eof
