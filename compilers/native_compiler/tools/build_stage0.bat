@echo off
REM ============================================================================
REM  rawr - stage0 bootstrap build
REM
REM  Builds the RawrXD native compiler with the host MSVC toolchain.
REM  This is stage0 only: the compiler it produces must be able to build
REM  itself (stage1) and then the stage1 compiler must be able to build
REM  itself again (stage2) with no host toolchain present.
REM
REM  Usage: build_stage0.bat [output_dir]
REM ============================================================================
setlocal enabledelayedexpansion

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage0") do set "OUT=%%~fI"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [ERROR] vcvars64.bat not found at "%VCVARS%"
    exit /b 1
)

call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] failed to initialise MSVC environment
    exit /b 1
)

if not exist "%OUT%" mkdir "%OUT%" 2>nul

echo === RawrXD Native Compiler - stage0 bootstrap ===
echo root:   %ROOT%
echo output: %OUT%
echo.

REM ---------------------------------------------------------------------------
REM  rawrstd - the dependency-free runtime the compiler is built on
REM ---------------------------------------------------------------------------
echo [1/3] building rawrstd...
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" ^
   /Fo:"%OUT%\\" ^
   "%ROOT%\rawrstd\src\sys.cpp" ^
   "%ROOT%\rawrstd\src\string.cpp" 2>&1
if errorlevel 1 (
    echo [FAIL] rawrstd
    exit /b 1
)
echo   [OK] rawrstd

REM ---------------------------------------------------------------------------
REM  Test harness
REM ---------------------------------------------------------------------------
echo [2/3] building rawrstd test...
cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" ^
   /Fe:"%OUT%\rawrstd_test.exe" ^
   "%ROOT%\tests\rawrstd_test.cpp" ^
   "%OUT%\sys.obj" "%OUT%\string.obj" 2>&1
if errorlevel 1 (
    echo [FAIL] rawrstd test
    exit /b 1
)
echo   [OK] rawrstd_test.exe

echo [3/3] running rawrstd test...
"%OUT%\rawrstd_test.exe"
if errorlevel 1 (
    echo [FAIL] rawrstd test FAILED
    exit /b 1
)

echo.
echo stage0 runtime foundation: PASS
exit /b 0
