@echo off
REM =============================================================================
REM RAWRXD Enterprise Kernel - 69 Compiler Integration Build Script
REM Builds: IDE Integration Layer + Smoke Test Suite
REM Architecture: x64 MASM (ML64)
REM =============================================================================

echo =================================================================
echo RAWRXD IDE-CI Integration Build System v14.7
echo 69 Compiler Backend Integration
echo =================================================================
echo.

REM Set up Visual Studio environment
set VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set ML64=%VS_PATH%\bin\Hostx64\x64\ml64.exe
set LINK=%VS_PATH%\bin\Hostx64\x64\link.exe

REM Verify tools exist
if not exist "%ML64%" (
    echo ERROR: ML64 not found at %ML64%
    exit /b 1
)

if not exist "%LINK%" (
    echo ERROR: LINK not found at %LINK%
    exit /b 1
)

echo [1/5] Tools verified: ML64 + LINK
echo.

REM Create output directory
if not exist bin mkdir bin

REM =============================================================================
REM Build Phase 1: IDE Integration Layer
REM =============================================================================
echo [2/5] Building IDE Integration Layer...
echo       - RAWRXD_IDE_Integration.asm
echo       - 69-slot compiler registry
echo       - CI kernel bridge

"%ML64%" /c /W3 /nologo /Zi /Fo bin\RAWRXD_IDE_Integration.obj ^
    RAWRXD_IDE_Integration.asm

if errorlevel 1 (
    echo ERROR: IDE Integration build failed
    exit /b 1
)

echo       OK: IDE Integration compiled successfully
echo.

REM =============================================================================
REM Build Phase 2: Smoke Test Suite
REM =============================================================================
echo [3/5] Building Smoke Test Suite...
echo       - RAWRXD_SmokeTest_69Compilers.asm
echo       - Tier 1-2-3 compiler validation
echo       - Integration test harness

"%ML64%" /c /W3 /nologo /Zi /Fo bin\RAWRXD_SmokeTest_69Compilers.obj ^
    RAWRXD_SmokeTest_69Compilers.asm

if errorlevel 1 (
    echo ERROR: Smoke Test build failed
    exit /b 1
)

echo       OK: Smoke Test Suite compiled successfully
echo.

REM =============================================================================
REM Build Phase 3: Link Integration Binary
REM =============================================================================
echo [4/5] Linking IDE Integration Binary...

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
    /OUT:bin\RAWRXD_IDE_Integration.exe ^
    bin\RAWRXD_IDE_Integration.obj ^
    kernel32.lib

if errorlevel 1 (
    echo ERROR: IDE Integration link failed
    exit /b 1
)

echo       OK: RAWRXD_IDE_Integration.exe created
echo.

REM =============================================================================
REM Build Phase 6: Roslyn Bridge Module
REM =============================================================================
echo [6/7] Building Roslyn CLI Bridge...
echo       - RAWRXD_Roslyn_Bridge.asm
echo       - Anonymous pipe architecture
echo       - csc.exe / dotnet build integration

"%ML64%" /c /W3 /nologo /Zi /Fo bin\RAWRXD_Roslyn_Bridge.obj ^
    RAWRXD_Roslyn_Bridge.asm

if errorlevel 1 (
    echo ERROR: Roslyn Bridge build failed
    exit /b 1
)

echo       OK: Roslyn Bridge compiled successfully
echo.

REM =============================================================================
REM Build Phase 7: Micro-Roslyn Syntax Engine
REM =============================================================================
echo [7/7] Building Micro-Roslyn Syntax Engine...
echo       - RAWRXD_MicroRoslyn.asm
echo       - Real-time C# validation
echo       - Zero external dependencies

"%ML64%" /c /W3 /nologo /Zi /Fo bin\RAWRXD_MicroRoslyn.obj ^
    RAWRXD_MicroRoslyn.asm

if errorlevel 1 (
    echo ERROR: Micro-Roslyn build failed
    exit /b 1
)

echo       OK: Micro-Roslyn compiled successfully
echo.

REM =============================================================================
REM Final Link: Complete IDE Integration Binary
REM =============================================================================
echo [FINAL] Linking complete IDE integration binary...

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
    /OUT:bin\RAWRXD_IDE_Integration.exe ^
    bin\RAWRXD_IDE_Integration.obj ^
    bin\RAWRXD_SmokeTest_69Compilers.obj ^
    bin\RAWRXD_Roslyn_Bridge.obj ^
    bin\RAWRXD_MicroRoslyn.obj ^
    kernel32.lib

if errorlevel 1 (
    echo ERROR: Final link failed
    exit /b 1
)

echo       OK: RAWRXD_IDE_Integration.exe created
echo.

echo =================================================================
echo BUILD COMPLETE: RAWRXD IDE Integration v14.7
echo =================================================================
echo Binaries:
echo   - bin\RAWRXD_IDE_Integration.exe
echo   - bin\RAWRXD_SmokeTest_69Compilers.exe
echo.
echo Features:
echo   - 69 Compiler Backend Integration
echo   - Roslyn CLI Bridge (csc.exe / dotnet)
echo   - Micro-Roslyn Syntax Engine
echo   - Enterprise CI Kernel (32 modules)
echo =================================================================

exit /b 0
    kernel32.lib

if errorlevel 1 (
    echo ERROR: Smoke Test link failed
    exit /b 1
)

echo       OK: RAWRXD_SmokeTest_69Compilers.exe created
echo.

REM =============================================================================
REM Build Summary
REM =============================================================================
echo =================================================================
echo BUILD COMPLETE
echo =================================================================
echo.
echo Output Files:
echo   - bin\RAWRXD_IDE_Integration.exe
echo   - bin\RAWRXD_SmokeTest_69Compilers.exe
echo.
echo Next Steps:
echo   1. Run: bin\RAWRXD_IDE_Integration.exe (Audit all 69 compilers)
echo   2. Run: bin\RAWRXD_SmokeTest_69Compilers.exe (Full smoke test)
echo   3. Verify: NO STUBS, ALL BLOCKERS ELIMINATED
echo.
echo =================================================================

exit /b 0
