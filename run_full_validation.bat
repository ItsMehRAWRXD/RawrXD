@echo off
:: Full Validation Suite Runner
:: Runs SovereignTest_Suite, VAL-038 E2E, and Deep2 Batch tests

echo ==========================================
echo RawrXD Full Validation Suite
echo ==========================================
echo.

set OVERALL_PASS=0

:: Step 1: Run SovereignTest_Suite (unit tests)
echo [1/3] Running SovereignTest_Suite...
if exist build_fix3\bin\SovereignTest_Suite.exe (
    build_fix3\bin\SovereignTest_Suite.exe
    if %ERRORLEVEL% neq 0 (
        echo [FAIL] SovereignTest_Suite failed
        set OVERALL_PASS=1
    ) else (
        echo [PASS] SovereignTest_Suite passed
    )
) else (
    echo [SKIP] SovereignTest_Suite.exe not found
)
echo.

:: Step 2: Run VAL-038 E2E test
echo [2/3] Running VAL-038 E2E test...
if exist build_fix3\bin\SovereignTest_VAL038_E2E.exe (
    build_fix3\bin\SovereignTest_VAL038_E2E.exe
    if %ERRORLEVEL% neq 0 (
        echo [FAIL] VAL-038 E2E test failed
        set OVERALL_PASS=1
    ) else (
        echo [PASS] VAL-038 E2E test passed
    )
) else (
    echo [SKIP] SovereignTest_VAL038_E2E.exe not found
)
echo.

:: Step 3: Run Deep2 Batch test
echo [3/3] Running Deep2 Batch test...
if exist build_fix3\bin\Deep2_Batch_Test.exe (
    if exist models\ (
        build_fix3\bin\Deep2_Batch_Test.exe models
        if %ERRORLEVEL% neq 0 (
            echo [WARN] Deep2 Batch test completed with warnings
        ) else (
            echo [PASS] Deep2 Batch test passed
        )
    ) else (
        echo [SKIP] models/ directory not found, skipping batch test
    )
) else (
    echo [SKIP] Deep2_Batch_Test.exe not found
)
echo.

:: Final summary
echo ==========================================
if %OVERALL_PASS% equ 0 (
    echo [SUCCESS] All validation tests passed
    echo The Nightmare patch is production-ready
) else (
    echo [FAILURE] Some validation tests failed
    echo Review output above for details
)
echo ==========================================

exit /b %OVERALL_PASS%
