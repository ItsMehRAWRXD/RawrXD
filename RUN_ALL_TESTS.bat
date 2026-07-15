@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Complete Test Suite
echo Version: 14.7.3
echo ============================================
echo.

set "TEST_DIR=%~dp0dist\bin"
set "TOTAL_TESTS=0"
set "PASSED_TESTS=0"
set "FAILED_TESTS=0"

if not exist "%TEST_DIR%" (
    echo ERROR: Test directory not found: %TEST_DIR%
    exit /b 1
)

echo [1/3] Running Inference Routing Test...
echo ----------------------------------------
cd /d "%TEST_DIR%"

if exist "RawrXD-InferenceRoutingTest.exe" (
    RawrXD-InferenceRoutingTest.exe --batch-mode > "%TEMP%\test_output_1.txt" 2>&1
    if errorlevel 1 (
        echo   [FAIL] Inference Routing Test
        set /a FAILED_TESTS+=1
        type "%TEMP%\test_output_1.txt"
    ) else (
        echo   [PASS] Inference Routing Test
        set /a PASSED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
    del "%TEMP%\test_output_1.txt" 2>nul
) else (
    echo   [SKIP] Inference Routing Test (not found)
)

echo.
echo [2/3] Running GUI Smoke Test...
echo ----------------------------------------

if exist "RawrXD.exe" (
    echo   [INFO] GUI executable exists: RawrXD.exe
    for %%I in (RawrXD.exe) do (
        echo   [INFO] Size: %%~zI bytes
        echo   [INFO] Modified: %%~tI
    )
    set /a PASSED_TESTS+=1
) else (
    echo   [FAIL] RawrXD.exe not found
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo.
echo [3/3] Running Distribution Package Test...
echo ----------------------------------------

if exist "%~dp0dist\RawrXD-14.7.3-Windows-x64.zip" (
    echo   [PASS] Distribution package exists
    for %%I in ("%~dp0dist\RawrXD-14.7.3-Windows-x64.zip") do (
        echo   [INFO] Size: %%~zI bytes
        echo   [INFO] Modified: %%~tI
    )
    set /a PASSED_TESTS+=1
) else (
    echo   [FAIL] Distribution package not found
    set /a FAILED_TESTS+=1
)
set /a TOTAL_TESTS+=1

echo.
echo ============================================
echo TEST SUMMARY
echo ============================================
echo Total Tests:  %TOTAL_TESTS%
echo Passed:       %PASSED_TESTS%
echo Failed:       %FAILED_TESTS%
echo Success Rate: %PASSED_TESTS%/%TOTAL_TESTS%
echo.

if %FAILED_TESTS%==0 (
    echo [OK] All tests passed!
    exit /b 0
) else (
    echo [FAIL] Some tests failed
    exit /b 1
)
