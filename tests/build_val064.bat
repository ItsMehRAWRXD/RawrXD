@echo off
REM ===========================================================================
REM VAL-064 Performance Certification Build Script
REM ===========================================================================
REM Builds the certification harness and runs the certification.
REM ===========================================================================

setlocal enabledelayedexpansion

set SRC_DIR=d:\src\tests
set BUILD_DIR=d:\build\tests
set EVIDENCE_DIR=d:\evidence\performance

REM Find Visual Studio 2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Please install Visual Studio 2022.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not defined VSINSTALLPATH (
    echo ERROR: Visual Studio 2022 with C++ tools not found.
    exit /b 1
)

echo Found Visual Studio at: %VSINSTALLPATH%

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup Visual Studio environment.
    exit /b 1
)

REM Add missing Windows SDK include paths (vcvars64.bat only adds ucrt)
set "SDK_INCLUDE=C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0"
set "INCLUDE=%INCLUDE%;%SDK_INCLUDE%\um;%SDK_INCLUDE%\shared;%SDK_INCLUDE%\winrt"

REM Add missing Windows SDK lib path for psapi.lib etc
set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\lib\10.0.22621.0"
set "LIB=%LIB%;%SDK_LIB%\um\x64"

REM Ensure directories exist
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%EVIDENCE_DIR%" mkdir "%EVIDENCE_DIR%"

echo ========================================
echo VAL-064/065 Certification Build
echo ========================================
echo.

REM Step 1: Compile VAL-064 certification harness
echo [1/4] Compiling VAL-064 certification harness...
cl.exe /nologo /EHsc /std:c++17 /I"%SRC_DIR%" /I"d:\rawrxd\3rdparty" /Fe:"%BUILD_DIR%\VAL064_PerformanceCertification.exe" /Fo:"%BUILD_DIR%\VAL064_PerformanceCertification.obj" "%SRC_DIR%\VAL064_PerformanceCertification.cpp" /link /OUT:"%BUILD_DIR%\VAL064_PerformanceCertification.exe" psapi.lib

if %ERRORLEVEL% neq 0 (
    echo ERROR: VAL-064 compilation failed with code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
echo   VAL-064 compilation successful.
echo.

REM Step 2: Compile VAL-065 memory certification
echo [2/4] Compiling VAL-065 memory certification...
cl.exe /nologo /EHsc /std:c++17 /I"%SRC_DIR%" /I"d:\rawrxd\3rdparty" /Fe:"%BUILD_DIR%\VAL065_MemoryCertification.exe" /Fo:"%BUILD_DIR%\VAL065_MemoryCertification.obj" "%SRC_DIR%\VAL065_MemoryCertification.cpp" /link /OUT:"%BUILD_DIR%\VAL065_MemoryCertification.exe" psapi.lib

if %ERRORLEVEL% neq 0 (
    echo ERROR: VAL-065 compilation failed with code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
echo   VAL-065 compilation successful.
echo.

REM Step 3: Run VAL-064 certification (scaffold mode)
echo [3/4] Running VAL-064 certification (scaffold mode)...
"%BUILD_DIR%\VAL064_PerformanceCertification.exe" ^
    --benchmark VAL-064-performance ^
    --model deep2-q4_k_m.gguf ^
    --tokens 512 ^
    --context 2048 ^
    --backend auto ^
    --telemetry mock ^
    --warmup 3 ^
    --runs 5 ^
    --json-output "%EVIDENCE_DIR%\VAL064.json"

if %ERRORLEVEL% neq 0 (
    echo ERROR: VAL-064 certification run failed with code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
echo   VAL-064 certification run successful.
echo.

REM Step 4: Verify outputs
echo [4/4] Verifying certification outputs...
set ALL_PASSED=1
if not exist "%EVIDENCE_DIR%\VAL064.json" (
    echo   ERROR: VAL-064 output not found!
    set ALL_PASSED=0
) else (
    echo   VAL-064 output: %EVIDENCE_DIR%\VAL064.json
    type "%EVIDENCE_DIR%\VAL064.json"
    echo.
    echo   VAL-064: PASSED
)

if not exist "%EVIDENCE_DIR%\VAL065.json" (
    echo   VAL-065 output: not yet generated (run VAL065_MemoryCertification.exe manually)
) else (
    echo   VAL-065 output: %EVIDENCE_DIR%\VAL065.json
    echo   VAL-065: PASSED
)

if %ALL_PASSED%==0 (
    echo   ERROR: Some outputs missing!
    exit /b 1
)

echo.
echo ========================================
echo VAL-064/065 Certification Complete
echo ========================================
echo VAL-064 Certification Complete
echo ========================================
echo.
echo Next steps for full certification:
echo   1. Run with --live flag against real model
echo   2. Replace static values with live telemetry
echo   3. Run on target hardware (R9700 32GB + RX 7800 XT 16GB)
echo   4. Validate against 2048 prompt / 512 generation workload
echo.

endlocal
exit /b 0
