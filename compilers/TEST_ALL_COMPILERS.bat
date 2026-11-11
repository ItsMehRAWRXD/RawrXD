@echo off
REM ===============================================================================
REM Omega-Polyglot Compiler Build and Test Script
REM Tests all compiler assembly sources and executables
REM ===============================================================================

echo ===============================================================================
echo Omega-Polyglot Compiler Build and Test Script
echo ===============================================================================
echo.

REM Set paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set SRC_DIR=%~dp0\assembly_source
set OBJ_DIR=%~dp0\obj_test
set BIN_DIR=%~dp0\bin_test
set LOG_DIR=%~dp0\test_logs

REM Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo Directories:
echo   Source: %SRC_DIR%
echo   Objects: %OBJ_DIR%
echo   Binaries: %BIN_DIR%
echo   Logs: %LOG_DIR%
echo.

REM Check ml64.exe exists
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at %ML64%
    echo Please install VS2022 Enterprise or update the path
    exit /b 1
)

echo Found ml64.exe: %ML64%
echo.

REM ===============================================================================
REM Test 1: Build Assembly Sources
echo ===============================================================================
echo Test 1: Building Assembly Source Files
echo ===============================================================================
echo.

set BUILD_COUNT=0
set BUILD_SUCCESS=0
set BUILD_FAIL=0

for %%f in ("%SRC_DIR%\*.asm") do (
    echo Building: %%~nxf
    set /a BUILD_COUNT+=1
    
    "%ML64%" /c /Fo"%OBJ_DIR%\%%~nf.obj" "%%f" > "%LOG_DIR%\%%~nf_build.log" 2>&1
    
    if !ERRORLEVEL! equ 0 (
        echo   [PASS] %%~nxf
echo   [PASS] %%~nxf >> "%LOG_DIR%\build_summary.log"
        set /a BUILD_SUCCESS+=1
    ) else (
        echo   [FAIL] %%~nxf - Check %LOG_DIR%\%%~nf_build.log
        echo   [FAIL] %%~nxf >> "%LOG_DIR%\build_summary.log"
        set /a BUILD_FAIL+=1
    )
)

echo.
echo Build Summary:
echo   Total:   %BUILD_COUNT%
echo   Success: %BUILD_SUCCESS%
echo   Failed:  %BUILD_FAIL%
echo.

REM ===============================================================================
REM Test 2: Test Existing Executables
echo ===============================================================================
echo Test 2: Testing Existing Compiler Executables
echo ===============================================================================
echo.

set EXE_COUNT=0
set EXE_WORKING=0
set EXE_SILENT=0

for %%f in ("%~dp0\*.exe") do (
    set /a EXE_COUNT+=1
    echo Testing: %%~nxf
    
    REM Try to run with --help and capture output
    "%%f" --help > "%LOG_DIR%\%%~nf_test.log" 2>&1
    set EXITCODE=!ERRORLEVEL!
    
    REM Check if file has content
    for %%A in ("%LOG_DIR%\%%~nf_test.log") do set SIZE=%%~zA
    
    if !SIZE! gtr 0 (
        echo   [WORKING] %%~nxf produces output
        echo   [WORKING] %%~nxf >> "%LOG_DIR%\exe_summary.log"
        set /a EXE_WORKING+=1
    ) else (
        echo   [SILENT] %%~nxf - No output (may need input file)
        echo   [SILENT] %%~nxf >> "%LOG_DIR%\exe_summary.log"
        set /a EXE_SILENT+=1
    )
)

echo.
echo Executable Summary:
echo   Total:    %EXE_COUNT%
echo   Working:  %EXE_WORKING%
echo   Silent:   %EXE_SILENT%
echo.

REM ===============================================================================
REM Test 3: Check Language Manifest
echo ===============================================================================
echo Test 3: Language Manifest Verification
echo ===============================================================================
echo.

if exist "%~dp0\languages_supported_manifest.json" (
    echo [PASS] Language manifest exists
    
    REM Count found languages (simple parsing)
    findstr /C:"\"found\"" "%~dp0\languages_supported_manifest.json" > nul
    if !ERRORLEVEL! equ 0 (
        echo [INFO] Found 'found' array in manifest
    )
    
    findstr /C:"\"missing\"" "%~dp0\languages_supported_manifest.json" > nul
    if !ERRORLEVEL! equ 0 (
        echo [INFO] Found 'missing' array in manifest
    )
) else (
    echo [FAIL] Language manifest not found
)

echo.

REM ===============================================================================
REM Summary
echo ===============================================================================
echo TEST SUMMARY
echo ===============================================================================
echo.
echo Build Results:
echo   Assembly files built: %BUILD_SUCCESS%/%BUILD_COUNT%
echo.
echo Executable Results:
echo   Working executables: %EXE_WORKING%/%EXE_COUNT%
echo   Silent executables:  %EXE_SILENT%/%EXE_COUNT%
echo.
echo Logs saved to: %LOG_DIR%
echo.

pause
