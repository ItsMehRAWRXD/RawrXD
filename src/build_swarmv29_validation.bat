@echo off
REM ==============================================================================
REM Build SwarmV29 Validation Harness
REM Compiles and links the C++ test harness with the static library
REM ==============================================================================

setlocal EnableDelayedExpansion

set VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64
set SRCDIR=c:\RawrXD\src
set OUTDIR=c:\RawrXD\src\pqc_build

echo [SwarmV29] Building Validation Harness...
echo.

REM Compile C++ harness
echo [1/2] Compiling SwarmV29_Validation_Harness.cpp...
"%VS_PATH%\cl.exe" /c /nologo /O2 /arch:AVX512 /EHsc /I"%SRCDIR%" ^
    /Fo"%OUTDIR%\SwarmV29_Validation_Harness.obj" ^
    "%SRCDIR%\SwarmV29_Validation_Harness.cpp"

if errorlevel 1 (
    echo [ERROR] Compilation failed.
    exit /b 1
)

REM Link with static library
echo [2/2] Linking with SwarmV29.lib...
"%VS_PATH%\link.exe" /NOLOGO /SUBSYSTEM:CONSOLE ^
    /OUT:"%OUTDIR%\SwarmV29_Validation.exe" ^
    "%OUTDIR%\SwarmV29_Validation_Harness.obj" ^
    "%OUTDIR%\SwarmV29.lib" ^
    kernel32.lib

if errorlevel 1 (
    echo [ERROR] Linking failed.
    exit /b 1
)

echo.
echo [SUCCESS] Validation harness built successfully.
echo Output: %OUTDIR%\SwarmV29_Validation.exe
echo.
echo To run tests: %OUTDIR%\SwarmV29_Validation.exe

endlocal