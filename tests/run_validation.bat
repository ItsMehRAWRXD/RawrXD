@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Validation Framework
echo Version: 15.0.0-dev
echo ============================================
echo.

set "TEST_DIR=%~dp0"
set "CATEGORY=%~1"
set "VERBOSE=0"
set "REPORT=0"

if "%~1"=="--verbose" set VERBOSE=1
if "%~1"=="--report" set REPORT=1
if "%~2"=="--verbose" set VERBOSE=1
if "%~2"=="--report" set REPORT=1

if "%CATEGORY%"=="--verbose" set CATEGORY=all
if "%CATEGORY%"=="--report" set CATEGORY=all
if "%CATEGORY%"=="" set CATEGORY=all

echo Running tests: %CATEGORY%
echo.

set "TOTAL_TESTS=0"
set "PASSED_TESTS=0"
set "FAILED_TESTS=0"

if /i "%CATEGORY%"=="all" (
    call :run_category "cpu" "CPU Tests"
    call :run_category "gpu" "GPU Tests"
    call :run_category "tokenizer" "Tokenizer Tests"
    call :run_category "gguf" "GGUF Tests"
    call :run_category "kernels" "Kernel Tests"
    call :run_category "transformer" "Transformer Tests"
    call :run_category "sampler" "Sampler Tests"
    call :run_category "integration" "Integration Tests"
) else (
    call :run_category "%CATEGORY%" "%CATEGORY% Tests"
)

echo.
echo ============================================
echo VALIDATION SUMMARY
echo ============================================
echo Total Tests:  %TOTAL_TESTS%
echo Passed:       %PASSED_TESTS%
echo Failed:       %FAILED_TESTS%
echo.

if %FAILED_TESTS%==0 (
    echo [OK] All tests passed!
    exit /b 0
) else (
    echo [FAIL] Some tests failed
    exit /b 1
)

:run_category
set "CAT_DIR=%~1"
set "CAT_NAME=%~2"

echo [%CAT_NAME%]

if exist "%TEST_DIR%\%CAT_DIR%\test_*.exe" (
    for %%f in ("%TEST_DIR%\%CAT_DIR%\test_*.exe") do (
        set /a TOTAL_TESTS+=1
        if %VERBOSE%==1 (
            "%%f"
        ) else (
            "%%f" > nul 2>&1
        )
        if errorlevel 1 (
            echo   [FAIL] %%~nf
            set /a FAILED_TESTS+=1
        ) else (
            echo   [PASS] %%~nf
            set /a PASSED_TESTS+=1
        )
    )
) else (
    echo   [SKIP] No tests found
)

echo.
goto :eof
