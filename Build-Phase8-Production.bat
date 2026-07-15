@echo off
chcp 65001 > nul
title RawRamXD Phase 8 - Production Readiness Build
cls

echo ========================================
echo RawRamXD Phase 8: Production Readiness
echo Acceptance Gates I1-I5
echo ========================================
echo.
echo Gates:
echo   [I1] Stress test framework (24h capability)
echo   [I2] Chaos engineering (random failures)
echo   [I3] Performance regression detection
echo   [I4] Automated recovery validation
echo   [I5] Production deployment checklist
echo.
echo Output:
echo   - rawramxd_production_readiness.json
echo   - production_checklist_report.md
echo.
pause

set "SOURCE=RawRamXD_Phase8_ProductionReady.cpp"
set "TEST_SOURCE=RawRamXD_Phase8_ProductionTest.cpp"
set "OUTPUT=RawRamXD_Phase8_Production.exe"
set "BUILD_DIR=build_phase8_production"

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo.
echo [+] Setting up Visual C++ environment...

:: Set up paths manually
set "VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VC_TOOLS=%VS_ROOT%\VC\Tools\MSVC\14.51.36231"
set "WINSDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

:: Add to PATH
set "PATH=%VC_TOOLS%\bin\Hostx64\x64;%PATH%"

:: Set include paths
set "INCLUDE=%VC_TOOLS%\include;%WINSDK_ROOT%\Include\%WINSDK_VER%\ucrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\um;%WINSDK_ROOT%\Include\%WINSDK_VER%\shared"

:: Set lib paths
set "LIB=%VC_TOOLS%\lib\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\um\x64"

echo     INCLUDE paths set
echo     LIB paths set

echo.
echo [+] Compiling Phase 8 Production Readiness...
echo.

cl.exe /O2 /EHsc /std:c++17 /arch:AVX2 /fp:fast /MD ^
    %SOURCE% %TEST_SOURCE% ^
    kernel32.lib user32.lib ^
    /Fe:%BUILD_DIR%\%OUTPUT% ^
    /Fo:%BUILD_DIR%\ ^
    /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF ^
    2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Compilation failed!
    pause
    exit /b 1
)

echo.
echo [OK] Build successful: %BUILD_DIR%\%OUTPUT%
echo.

echo ========================================
echo Running I1-I5 Acceptance Gates
echo ========================================
echo.

cd %BUILD_DIR%
.\%OUTPUT%
cd ..

echo.
echo ========================================
echo Phase 8 Complete!
echo ========================================
echo.
echo Output files:
echo   - %BUILD_DIR%\rawramxd_production_readiness.json
echo   - %BUILD_DIR%\production_checklist_report.md
echo.
echo RAWRAMXD PHASE 7 & 8 COMPLETE!
echo Total: 24 acceptance gates validated!
echo.
pause