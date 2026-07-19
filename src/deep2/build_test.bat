@echo off
REM ============================================================================
REM build_test.bat - Build and run Deep2 Engine tests
REM ============================================================================

setlocal enabledelayedexpansion

echo [+] Building Deep2 Engine Test Suite...
echo.

REM Check for ml64.exe
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist "%ML64%" (
    echo [-] ERROR: ml64.exe not found
    exit /b 1
)

REM Create output directory
if not exist "obj" mkdir obj
if not exist "bin" mkdir bin

echo [+] Assembling MASM kernels...
"%ML64%" /c /nologo /Fo obj\deep2_kernel.obj deep2_kernel.asm
if errorlevel 1 (
    echo [-] ERROR: Failed to assemble deep2_kernel.asm
    exit /b 1
)
echo [+] deep2_kernel.asm assembled successfully

echo.
echo [+] Compiling C++ wrapper...
"%CL%" /c /nologo /EHsc /O2 /arch:AVX2 /Fo obj\Deep2.obj Deep2.cpp
if errorlevel 1 (
    echo [-] ERROR: Failed to compile Deep2.cpp
    exit /b 1
)
echo [+] Deep2.cpp compiled successfully

echo.
echo [+] Compiling test harness...
"%CL%" /c /nologo /EHsc /O2 /arch:AVX2 /Fo obj\test_deep2.obj test_deep2.cpp
if errorlevel 1 (
    echo [-] ERROR: Failed to compile test_deep2.cpp
    exit /b 1
)
echo [+] test_deep2.cpp compiled successfully

echo.
echo [+] Linking test executable...
"%LINK%" /nologo /OUT:bin\test_deep2.exe obj\test_deep2.obj obj\Deep2.obj obj\deep2_kernel.obj
if errorlevel 1 (
    echo [-] ERROR: Failed to link test executable
    exit /b 1
)
echo [+] test_deep2.exe linked successfully

echo.
echo [+] Build complete!
echo.
echo     Executable: bin\test_deep2.exe
echo.

REM Run tests
echo [+] Running tests...
echo.
bin\test_deep2.exe
set TEST_RESULT=%ERRORLEVEL%

echo.
if %TEST_RESULT% equ 0 (
    echo [+] All tests passed!
) else (
    echo [-] Some tests failed.
)

endlocal
exit /b %TEST_RESULT%
