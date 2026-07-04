@echo off
:: Build and run trace-validated test

echo Building Trace-Validated Test...
echo.

:: Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    echo ERROR: Visual Studio environment not found
    exit /b 1
)

:: Create output directory
if not exist "d:\rawrxd\build\tests" mkdir "d:\rawrxd\build\tests"

:: Compile test
echo Compiling trace_validated_test.cpp...
cl.exe /std:c++20 /EHsc /O2 /Fe:d:\rawrxd\build\tests\trace_validated_test.exe ^
    d:\rawrxd\src\script\tests\trace_validated_test.cpp ^
    d:\rawrxd\src\script\runtime\trace_validator.cpp ^
    d:\rawrxd\src\script\runtime\runtime_minimal.cpp ^
    /I d:\rawrxd\src\script ^
    /link kernel32.lib ^
    2>nul

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo.
echo Build successful!
echo.

:: Run test
echo Running trace-validated test...
echo.
d:\rawrxd\build\tests\trace_validated_test.exe

set TEST_RESULT=%ERRORLEVEL%

echo.
if %TEST_RESULT% equ 0 (
    echo ALL TESTS PASSED
) else (
    echo TESTS FAILED
)

exit /b %TEST_RESULT%
