@echo off
REM d:\rawrxd\phase4_build.bat
REM Phase 4 Final Milestones Build Script

echo Building Phase 4 Components...
echo.

cd /d d:\rawrxd

REM Set up Visual Studio environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo Warning: Could not set up VS environment, trying direct paths...
)

echo [1/3] Building MASM Node.js Engine...
cd masm_node
ml64 /c /W3 /Fo js_engine.obj js_engine.asm
if errorlevel 1 (
    echo MASM compilation failed
    exit /b 1
)

link /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:masm_node.exe js_engine.obj msvcrt.lib kernel32.lib legacy_stdio_definitions.lib
if errorlevel 1 (
    echo Linking failed
    exit /b 1
)
cd ..

echo [2/3] Building Titan Gold Master Certification...
cd titan
cl /EHsc /O2 /Fe:titan_gold_master.exe gold_master_certification.cpp
if errorlevel 1 (
    echo Titan compilation failed
    exit /b 1
)
cd ..

echo [3/3] Building Production Signoff...
cd signoff
cl /EHsc /O2 /Fe:production_signoff.exe production_signoff.cpp
if errorlevel 1 (
    echo Signoff compilation failed
    exit /b 1
)
cd ..

echo.
echo ============================================================
echo   PHASE 4 COMPLETE!
echo   - MASM Node.js Engine: masm_node\masm_node.exe
echo   - Titan Gold Master:   titan\titan_gold_master.exe
echo   - Production Signoff:  signoff\production_signoff.exe
echo ============================================================

echo.
echo Running Production Signoff...
signoff\production_signoff.exe

echo.
echo Running Titan Gold Master Certification (100 cycles)...
titan\titan_gold_master.exe

echo.
echo ============================================================
echo   ALL PHASE 4 MILESTONES COMPLETE!
echo ============================================================
