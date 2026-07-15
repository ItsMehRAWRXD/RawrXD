@echo off
REM Build stress tests

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to setup VS2022 environment
    exit /b 1
)

echo Building fuzz test...
cl /EHsc /O2 /W4 test_fuzz.c /Fetest_fuzz.exe
if %ERRORLEVEL% neq 0 (
    echo Fuzz test build failed
    exit /b 1
)

echo Building memory test...
cl /EHsc /O2 /W4 test_memory.c /Fetest_memory.exe
if %ERRORLEVEL% neq 0 (
    echo Memory test build failed
    exit /b 1
)

echo.
echo Build complete!
echo   - test_fuzz.exe
echo   - test_memory.exe
