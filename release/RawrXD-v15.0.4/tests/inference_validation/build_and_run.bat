@echo off
REM Build and run Numerical Inference Equivalence Harness

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to setup VS2022 environment
    exit /b 1
)

echo Building Numerical Equivalence Harness...
cl /EHsc /O2 /W4 /arch:AVX2 numerical_equivalence_harness.cpp /FeNumericalEquivalenceHarness.exe
if %ERRORLEVEL% neq 0 (
    echo Build failed
    exit /b 1
)

echo.
echo Running validation...
echo.

REM Create directories if they don't exist
if not exist "rawrxd_outputs" mkdir rawrxd_outputs
if not exist "reference_outputs" mkdir reference_outputs
if not exist "validation_results" mkdir validation_results

REM Run the harness
NumericalEquivalenceHarness.exe rawrxd_outputs reference_outputs validation_results

exit /b %ERRORLEVEL%
