@echo off
REM Quick AMX/INT8 Test - Compile and Run
REM Usage: quick_test.bat [msvc|gcc]

cd /d d:\rawrxd

set COMPILER=%1
if "%COMPILER%"=="" set COMPILER=msvc

echo ==========================================
echo Quick AMX/INT8 Validation Test
echo Compiler: %COMPILER%
echo ==========================================
echo.

if "%COMPILER%"=="msvc" (
    echo Using Microsoft Visual C++...
    
    REM Find VS2022
    set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "%VSWHERE%" (
        echo ERROR: vswhere.exe not found. Please run from Developer Command Prompt.
        exit /b 1
    )
    
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
        set "VSROOT=%%i"
    )
    
    call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
    
    cl.exe /O2 /arch:AVX512 /EHsc /nologo quick_amx_test.cpp /Fe:quick_amx_test.exe
    
    if %ERRORLEVEL% neq 0 (
        echo Compilation failed!
        exit /b 1
    )
) else if "%COMPILER%"=="gcc" (
    echo Using MinGW GCC...
    
    g++ -O3 -march=native -o quick_amx_test.exe quick_amx_test.cpp
    
    if %ERRORLEVEL% neq 0 (
        echo Compilation failed!
        exit /b 1
    )
) else (
    echo Unknown compiler: %COMPILER%
    echo Usage: quick_test.bat [msvc^|gcc]
    exit /b 1
)

echo.
echo ==========================================
echo Compilation successful!
echo Running test...
echo ==========================================
echo.

quick_amx_test.exe

set TEST_RESULT=%ERRORLEVEL%

echo.
echo ==========================================
if %TEST_RESULT%==0 (
    echo TEST PASSED
) else (
    echo TEST FAILED with exit code %TEST_RESULT%
)
echo ==========================================

exit /b %TEST_RESULT%
