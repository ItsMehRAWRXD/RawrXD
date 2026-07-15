@echo off
setlocal EnableDelayedExpansion

:: RawrXD Build and Test Master Script
:: One command to build everything and run all tests

echo ============================================
echo RawrXD Build and Test System
echo ============================================
echo.

set "ROOT_DIR=%~dp0"
set "TESTS_DIR=%ROOT_DIR%tests"
set "BUILD_STATUS=0"
set "COMPILE_COUNT=0"
set "FAIL_COUNT=0"

:: Colors (Windows 10+)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "RESET=[0m"

echo [INFO] Starting build process...
echo [INFO] Root: %ROOT_DIR%
echo.

:: Step 1: Create reports directory
if not exist "%TESTS_DIR%\reports" mkdir "%TESTS_DIR%\reports"

:: Step 2: Compile Core Kernel Tests
echo ============================================
echo Building Core Kernel Tests
echo ============================================

call :compile_category "cpu" 2
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

call :compile_category "tokenizer" 1
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

call :compile_category "gguf" 1
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

call :compile_category "kernels" 8
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

call :compile_category "sampler" 1
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

call :compile_category "integration" 1
if !ERRORLEVEL! neq 0 set "BUILD_STATUS=1"

:: Step 3: Compile Regression Tests
echo.
echo ============================================
echo Building Regression Tests
echo ============================================

cd /d "%TESTS_DIR%\regression"
if exist "test_regression.c" (
    echo [BUILD] test_regression.c
    gcc -O2 -o test_regression.exe test_regression.c -lm 2>nul
    if !ERRORLEVEL! equ 0 (
        echo   %GREEN%OK%RESET%
        set /a COMPILE_COUNT+=1
    ) else (
        echo   %RED%FAIL%RESET%
        set /a FAIL_COUNT+=1
        set "BUILD_STATUS=1"
    )
)

:: Step 4: Compile Performance Tests
echo.
echo ============================================
echo Building Performance Tests
echo ============================================

cd /d "%TESTS_DIR%\performance"
if exist "perf_quick.c" (
    echo [BUILD] perf_quick.c
    gcc -O2 -o perf_quick.exe perf_quick.c -lm 2>nul
    if !ERRORLEVEL! equ 0 (
        echo   %GREEN%OK%RESET%
        copy /y perf_quick.exe test_perf_quick.exe >nul
        set /a COMPILE_COUNT+=1
    ) else (
        echo   %RED%FAIL%RESET%
        set /a FAIL_COUNT+=1
        set "BUILD_STATUS=1"
    )
)

:: Step 5: Compile Stress Tests
echo.
echo ============================================
echo Building Stress Tests
echo ============================================

cd /d "%TESTS_DIR%\stress"
if exist "test_stress_kernels.c" (
    echo [BUILD] test_stress_kernels.c
    gcc -O2 -o test_stress_kernels.exe test_stress_kernels.c -lm 2>nul
    if !ERRORLEVEL! equ 0 (
        echo   %GREEN%OK%RESET%
        set /a COMPILE_COUNT+=1
    ) else (
        echo   %RED%FAIL%RESET%
        set /a FAIL_COUNT+=1
        set "BUILD_STATUS=1"
    )
)

:: Step 6: Generate Reference Data
echo.
echo ============================================
echo Generating Reference Data
echo ============================================

cd /d "%ROOT_DIR%\reference"
if exist "generate_reference.c" (
    echo [BUILD] generate_reference.c
    gcc -O2 -o generate_reference.exe generate_reference.c -lm 2>nul
    if !ERRORLEVEL! equ 0 (
        echo   %GREEN%OK%RESET%
        echo [RUN] Generating reference data...
        .\generate_reference.exe >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            echo   %GREEN%Reference data generated%RESET%
        ) else (
            echo   %YELLOW%Warning: Reference generation failed%RESET%
        )
    ) else (
        echo   %RED%FAIL%RESET%
        set /a FAIL_COUNT+=1
    )
)

:: Step 7: Run Tests
echo.
echo ============================================
echo Running Test Suite
echo ============================================

cd /d "%TESTS_DIR%"

echo [TEST] Running validation suite...
.\run_validation.bat > "%TESTS_DIR%\reports\test_output.txt" 2>&1
if !ERRORLEVEL! equ 0 (
    echo   %GREEN%All tests passed%RESET%
) else (
    echo   %RED%Some tests failed%RESET%
    set "BUILD_STATUS=1"
)

:: Step 8: Generate Report
echo.
echo ============================================
echo Generating Report
echo ============================================

python run_all.py --all > "%TESTS_DIR%\reports\unified_output.txt" 2>&1
if !ERRORLEVEL! equ 0 (
    echo   %GREEN%Report generated%RESET%
) else (
    echo   %YELLOW%Report generation issues%RESET%
)

:: Summary
echo.
echo ============================================
echo Build Summary
echo ============================================
echo Components compiled: %COMPILE_COUNT%
echo Compile failures:   %FAIL_COUNT%
echo.

if %BUILD_STATUS% equ 0 (
    echo %GREEN%============================================%RESET%
    echo %GREEN%  BUILD SUCCESSFUL%RESET%
    echo %GREEN%============================================%RESET%
    echo.
    echo Next steps:
    echo   - View dashboard: tests\dashboard.html
    echo   - Run live server: python tests\dashboard_server.py
    echo   - See reports: tests\reports\
    exit /b 0
) else (
    echo %RED%============================================%RESET%
    echo %RED%  BUILD FAILED%RESET%
    echo %RED%============================================%RESET%
    echo.
    echo Check errors above and fix issues.
    exit /b 1
)

:: Subroutines
:compile_category
set "CAT_DIR=%~1"
set "EXPECTED=%~2"
set "CAT_PATH=%TESTS_DIR%\%CAT_DIR%"

if not exist "%CAT_PATH%" (
    echo [SKIP] %CAT_DIR%: Directory not found
    exit /b 0
)

echo.
echo [%CAT_DIR%]
set "COMPILED=0"

for %%f in ("%CAT_PATH%\test_*.c") do (
    set "BASE_NAME=%%~nf"
    set "EXE_PATH=%CAT_PATH%\!BASE_NAME!.exe"
    
    echo [BUILD] %%~nf.c
    gcc -O2 -o "!EXE_PATH!" "%%f" -lm 2>nul
    
    if !ERRORLEVEL! equ 0 (
        echo   %GREEN%OK%RESET%
        set /a COMPILE_COUNT+=1
        set /a COMPILED+=1
    ) else (
        echo   %RED%FAIL%RESET%
        set /a FAIL_COUNT+=1
    )
)

if %COMPILED% equ 0 (
    echo   No source files found
)

exit /b 0
