@echo off
REM ============================================================================
REM build_deep2.bat - Build Deep2 Engine
REM Pure MASM x64 + C++ implementation, zero dependencies
REM ============================================================================

setlocal enabledelayedexpansion

echo [+] Building Deep2 Engine...
echo.

REM Check for ml64.exe
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
if not exist "%ML64%" (
    echo [-] ERROR: ml64.exe not found at %ML64%
    echo [!] Please install Visual Studio 2022 with C++ build tools
    exit /b 1
)

REM Check for cl.exe
set "CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
if not exist "%CL%" (
    echo [-] ERROR: cl.exe not found at %CL%
    echo [!] Please install Visual Studio 2022 with C++ build tools
    exit /b 1
)

REM Create output directory
if not exist "obj" mkdir obj
if not exist "lib" mkdir lib

echo [+] Assembling MASM kernels...
echo.

REM Assemble deep2_kernel.asm
"%ML64%" /c /nologo /Fo obj\deep2_kernel.obj deep2_kernel.asm
if errorlevel 1 (
    echo [-] ERROR: Failed to assemble deep2_kernel.asm
    exit /b 1
)
echo [+] deep2_kernel.asm assembled successfully

echo.
echo [+] Compiling C++ wrapper...
echo.

REM Compile Deep2.cpp
"%CL%" /c /nologo /EHsc /O2 /arch:AVX2 /Fo obj\Deep2.obj Deep2.cpp
if errorlevel 1 (
    echo [-] ERROR: Failed to compile Deep2.cpp
    exit /b 1
)
echo [+] Deep2.cpp compiled successfully

echo.
echo [+] Creating static library...
echo.

REM Create static library
set "LIBTOOL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"
"%LIBTOOL%" /nologo /out:lib\Deep2.lib obj\deep2_kernel.obj obj\Deep2.obj
if errorlevel 1 (
    echo [-] ERROR: Failed to create static library
    exit /b 1
)

echo.
echo [+] Deep2 Engine build complete!
echo.
echo     Library: lib\Deep2.lib
echo     Objects: obj\deep2_kernel.obj, obj\Deep2.obj
echo.
echo [+] CPU Features:
echo     AVX2:    Supported
echo     AVX512:  %AVX512%
echo.

endlocal
