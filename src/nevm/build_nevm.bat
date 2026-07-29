@echo off
::============================================================================
:: build_nevm.bat
:: RawrXD N-EVM Validation Framework - Build Script
:: CI-ready build for all validation tools
::============================================================================

setlocal EnableDelayedExpansion

:: Configuration
set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\build"
set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"

:: Ensure build directory exists
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Set up Visual Studio environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1

:: Compiler flags
set "CXXFLAGS=/std:c++17 /O2 /W4 /EHsc /I%SRC_DIR%"
set "CXXFLAGS=%CXXFLAGS% /I%SRC_DIR%\..\..\third_party\jsoncpp\include"
set "CXXFLAGS=%CXXFLAGS% /D_CRT_SECURE_NO_WARNINGS"
set "LDFLAGS=/LTCG"

:: JSONCPP library path
set "JSONCPP_LIB=%SRC_DIR%\..\..\third_party\jsoncpp\lib\jsoncpp.lib"

echo =============================================================================
echo RawrXD N-EVM Validation Framework Build
echo =============================================================================
echo.

:: Build individual components
echo [1/13] Building math mode utilities...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_math_mode.obj" "%SRC_DIR%\nevm_math_mode.cpp" > nul
if errorlevel 1 goto :error

echo [2/10] Building determinism safeguards...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_determinism_safeguards.obj" "%SRC_DIR%\nevm_determinism_safeguards.cpp" > nul
if errorlevel 1 goto :error

echo [3/10] Building KV integrity system...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_kv_integrity.obj" "%SRC_DIR%\nevm_kv_integrity.cpp" > nul
if errorlevel 1 goto :error

echo [4/10] Building execution plan version...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_execution_plan_version.obj" "%SRC_DIR%\nevm_execution_plan_version.cpp" > nul
if errorlevel 1 goto :error

echo [5/10] Building extended stress test...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_extended_stress_test.obj" "%SRC_DIR%\nevm_extended_stress_test.cpp" > nul
if errorlevel 1 goto :error

echo [6/10] Building validation schema...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_validation_schema.obj" "%SRC_DIR%\nevm_validation_schema.cpp" > nul
if errorlevel 1 goto :error

echo [7/10] Building performance thresholds...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_performance_thresholds.obj" "%SRC_DIR%\nevm_performance_thresholds.cpp" > nul
if errorlevel 1 goto :error

echo [8/10] Building failure artifacts...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_failure_artifacts.obj" "%SRC_DIR%\nevm_failure_artifacts.cpp" > nul
if errorlevel 1 goto :error

echo [9/10] Building kernel provenance...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_kernel_provenance.obj" "%SRC_DIR%\nevm_kernel_provenance.cpp" > nul
if errorlevel 1 goto :error

echo [10/14] Building golden output tests...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_golden_output.obj" "%SRC_DIR%\nevm_golden_output.cpp" > nul
if errorlevel 1 goto :error

echo [11/14] Building golden output generator...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_generate_golden.obj" "%SRC_DIR%\nevm_generate_golden.cpp" > nul
if errorlevel 1 goto :error

echo [12/14] Building parallel executor...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_parallel_executor.obj" "%SRC_DIR%\nevm_parallel_executor.cpp" > nul
if errorlevel 1 goto :error

echo [13/14] Building replay harness...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\nevm_replay_harness.obj" "%SRC_DIR%\nevm_replay_harness.cpp" > nul
if errorlevel 1 goto :error

echo [14/14] Building unified validator...

:: Link unified validator
echo.
echo Linking unified validator...
link.exe %LDFLAGS% /OUT:"%BUILD_DIR%\nevm_validate.exe" ^
    "%BUILD_DIR%\nevm_validate.obj" ^
    "%BUILD_DIR%\nevm_math_mode.obj" ^
    "%BUILD_DIR%\nevm_determinism_safeguards.obj" ^
    "%BUILD_DIR%\nevm_kv_integrity.obj" ^
    "%BUILD_DIR%\nevm_execution_plan_version.obj" ^
    "%BUILD_DIR%\nevm_extended_stress_test.obj" ^
    "%BUILD_DIR%\nevm_validation_schema.obj" ^
    "%BUILD_DIR%\nevm_performance_thresholds.obj" ^
    "%BUILD_DIR%\nevm_failure_artifacts.obj" ^
    "%BUILD_DIR%\nevm_kernel_provenance.obj" ^
    "%BUILD_DIR%\nevm_golden_output.obj" ^
    "%BUILD_DIR%\nevm_parallel_executor.obj" ^
    "%BUILD_DIR%\nevm_replay_harness.obj" ^
    "%JSONCPP_LIB%" > nul
if errorlevel 1 goto :error

:: Link golden output generator
echo Linking golden output generator...
link.exe %LDFLAGS% /OUT:"%BUILD_DIR%\nevm_generate_golden.exe" ^
    "%BUILD_DIR%\nevm_generate_golden.obj" ^
    "%BUILD_DIR%\nevm_math_mode.obj" ^
    "%BUILD_DIR%\nevm_golden_output.obj" ^
    "%JSONCPP_LIB%" > nul
if errorlevel 1 goto :error

:: Verify build
echo.
echo =============================================================================
echo Build Summary
echo =============================================================================

if exist "%BUILD_DIR%\nevm_validate.exe" (
    echo [OK] nevm_validate.exe
    for %%F in ("%BUILD_DIR%\nevm_validate.exe") do (
        echo      Size: %%~zF bytes
    )
) else (
    echo [FAIL] nevm_validate.exe not found
    goto :error
)

if exist "%BUILD_DIR%\nevm_generate_golden.exe" (
    echo [OK] nevm_generate_golden.exe
    for %%F in ("%BUILD_DIR%\nevm_generate_golden.exe") do (
        echo      Size: %%~zF bytes
    )
) else (
    echo [FAIL] nevm_generate_golden.exe not found
    goto :error
)

echo.
echo =============================================================================
echo Build Complete
echo =============================================================================
echo.
echo Usage:
echo   nevm_validate.exe model.gguf --mode=pr_check    (Fast PR validation)
echo   nevm_validate.exe model.gguf --mode=nightly     (Full nightly validation)
echo   nevm_validate.exe model.gguf --baseline=baseline.json  (With regression check)
echo   nevm_validate.exe model.gguf --golden=golden_output    (With golden output test)
echo   nevm_generate_golden.exe model.gguf -p "Hello world" -o golden_output  (Generate golden)
echo   nevm_validate.exe --help                          (Show all options)
echo.
echo Exit Codes:
echo   0  - All gates passed
echo   1  - Correctness failure
echo   2  - Performance regression
echo   3  - Stability failure
echo   4  - Environment failure
echo   5  - Invalid model
echo   6  - Schema mismatch
echo.

exit /b 0

:error
echo.
echo =============================================================================
echo BUILD FAILED
echo =============================================================================
exit /b 1
