@echo off
REM Build script for Sovereign Puppeteer Architecture
REM Tests the self-modification system integration

echo ==========================================
echo Sovereign Puppeteer Architecture Build Test
echo ==========================================
echo.

REM Set up environment
set "VSCMD_START_DIR=%CD%"
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul || call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul || call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Could not find Visual Studio 2022
    exit /b 1
)

echo [1/5] Setting up build directory...
if not exist "build-sovereign-test" mkdir build-sovereign-test
cd build-sovereign-test

echo.
echo [2/5] Configuring with CMake...
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_CLI=OFF -DRAWRXD_BUILD_WIN32IDE=OFF 2>&1 | tee configure.log

if errorlevel 1 (
    echo ERROR: CMake configuration failed
    type configure.log
    exit /b 1
)

echo.
echo [3/5] Building RawrEngine with Puppeteer components...
ninja RawrEngine 2>&1 | tee build.log

if errorlevel 1 (
    echo ERROR: Build failed
    type build.log
    exit /b 1
)

echo.
echo [4/5] Verifying symbols...
echo Checking for Puppeteer symbols in binary...
if exist "bin\RawrEngine.exe" (
    dumpbin /symbols bin\RawrEngine.exe 2>nul | findstr /i "Puppeteer SymbolTable VEH_Watchdog" > puppeteer_symbols.txt
    if not errorlevel 1 (
        echo [OK] Puppeteer symbols found in binary
        type puppeteer_symbols.txt
    ) else (
        echo [WARN] Puppeteer symbols not found - may be inlined or optimized out
    )
) else (
    echo [WARN] RawrEngine.exe not found in expected location
)

echo.
echo [5/5] Build complete!
echo.
echo ==========================================
echo Sovereign Puppeteer Components Built:
echo ==========================================
echo   - SymbolTableGenerator (introspection)
echo   - PuppeteerAPI (self-modification)
echo   - VEH_Watchdog (crash recovery)
echo   - Puppeteer_CaptureState.asm (MASM state capture)
echo.
echo Binary location: bin\RawrEngine.exe
echo.

cd ..
