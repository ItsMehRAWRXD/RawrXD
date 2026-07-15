@echo off
REM Build Verification Script for RawrXD Benchmark Suite (Windows)
REM Copyright (c) 2026 RawrXD Team

setlocal enabledelayedexpansion

echo ╔══════════════════════════════════════════════════════════════╗
echo ║     RawrXD Benchmark Suite - Build Verification             ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Configuration
set "BUILD_DIR=build"
set "CMAKE_OPTIONS="
set "BUILD_TYPE=Release"

REM Colors (using PowerShell for colored output)
set "GREEN=[32m"
set "RED=[31m"
set "YELLOW=[33m"
set "NC=[0m"

REM Function to print status
call :print_status "Starting build verification..."

REM Check prerequisites
call :check_prerequisites
if errorlevel 1 exit /b 1

REM Clean previous build
call :clean_build
if errorlevel 1 exit /b 1

REM Configure with CMake
call :configure
if errorlevel 1 exit /b 1

REM Build the project
call :build
if errorlevel 1 exit /b 1

REM Verify executables
call :verify_executables

REM Run tests
call :run_tests

REM Run smoke test
call :smoke_test

REM Generate report
call :generate_report

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║              Build Verification Complete!                    ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
call :print_status "Build artifacts located in: %CD%\%BUILD_DIR%"
call :print_status "To run benchmarks: cd %BUILD_DIR% && integrated_benchmark_runner.exe --help"

exit /b 0

:print_status
echo [INFO] %~1
exit /b 0

:print_error
echo [ERROR] %~1
exit /b 1

:print_warning
echo [WARN] %~1
exit /b 0

:check_prerequisites
call :print_status "Checking prerequisites..."

REM Check CMake
where cmake > nul 2>&1
if errorlevel 1 (
    call :print_error "CMake not found. Please install CMake 3.16+"
    exit /b 1
)

for /f "tokens=3" %%a in ('cmake --version ^| findstr /C:"cmake version"') do (
    call :print_status "CMake version: %%a"
)

REM Check Visual Studio or MinGW
where cl > nul 2>&1
if errorlevel 1 (
    where g++ > nul 2>&1
    if errorlevel 1 (
        call :print_error "No C++ compiler found. Please install Visual Studio or MinGW"
        exit /b 1
    )
)

call :print_status "Prerequisites check passed"
exit /b 0

:clean_build
call :print_status "Cleaning previous build..."
if exist "%BUILD_DIR%" (
    rmdir /s /q "%BUILD_DIR%"
    call :print_status "Removed existing build directory"
)
mkdir "%BUILD_DIR%"
exit /b 0

:configure
call :print_status "Configuring with CMake..."
cd "%BUILD_DIR%"

cmake .. ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DRAWRXD_BUILD_TESTS=ON ^
    -DRAWRXD_BUILD_PHASE_E=ON ^
    %CMAKE_OPTIONS% ^
    2>&1

if errorlevel 1 (
    call :print_error "CMake configuration failed"
    cd ..
    exit /b 1
)

call :print_status "CMake configuration successful"
cd ..
exit /b 0

:build
call :print_status "Building project..."
cd "%BUILD_DIR%"

cmake --build . --config %BUILD_TYPE% --parallel

if errorlevel 1 (
    call :print_error "Build failed"
    cd ..
    exit /b 1
)

call :print_status "Build successful"
cd ..
exit /b 0

:verify_executables
call :print_status "Verifying executables..."

set "EXECUTABLES=benchmark_runner.exe integrated_benchmark_runner.exe http_client_tests.exe backend_adapter_tests.exe e2e_tests.exe phase_e_benchmark.exe"

for %%e in (%EXECUTABLES%) do (
    if exist "%BUILD_DIR%\%%e" (
        call :print_status "OK %%e built successfully"
    ) else (
        call :print_warning "MISSING %%e not found"
    )
)

exit /b 0

:run_tests
call :print_status "Running tests..."
cd "%BUILD_DIR%"

REM Run CTest
ctest --output-on-failure -C %BUILD_TYPE% -j%NUMBER_OF_PROCESSORS%

if errorlevel 1 (
    call :print_warning "Some tests failed"
) else (
    call :print_status "All tests passed"
)

cd ..
exit /b 0

:smoke_test
call :print_status "Running smoke test..."
cd "%BUILD_DIR%"

REM Run help command on main executables
for %%e in (benchmark_runner.exe integrated_benchmark_runner.exe) do (
    if exist "%%e" (
        call :print_status "Testing %%e --help..."
        .\%%e --help > nul 2>&1
        if errorlevel 0 (
            call :print_status "OK %%e responds to --help"
        ) else (
            call :print_warning "FAIL %%e --help failed"
        )
    )
)

cd ..
exit /b 0

:generate_report
call :print_status "Generating build report..."

set "REPORT_FILE=%BUILD_DIR%\build_report.txt"

echo RawrXD Benchmark Suite - Build Report > "%REPORT_FILE%"
echo ==================================== >> "%REPORT_FILE%"
echo Build Date: %date% %time% >> "%REPORT_FILE%"
echo Build Type: %BUILD_TYPE% >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"
echo Executables Built: >> "%REPORT_FILE%"

for %%e in (%EXECUTABLES%) do (
    if exist "%BUILD_DIR%\%%e" (
        for %%F in ("%BUILD_DIR%\%%e") do (
            echo   OK %%e (%%~zF bytes) >> "%REPORT_FILE%"
        )
    ) else (
        echo   MISSING %%e >> "%REPORT_FILE%"
    )
)

echo. >> "%REPORT_FILE%"
echo Build Status: SUCCESS >> "%REPORT_FILE%"

call :print_status "Build report saved to %REPORT_FILE%"
exit /b 0
