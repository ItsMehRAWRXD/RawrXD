@echo off
REM ============================================================================
REM RawrXD Runtime Packaging Script
REM VAL-030: Standalone Runtime Release
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set VERSION=1.0.0
set BUILD_CONFIG=Release
set OUTPUT_DIR=dist\RawrXD_Runtime_v%VERSION%
set SOURCE_ROOT=%CD%

echo ============================================================================
echo RawrXD Runtime Packaging - Version %VERSION%
echo ============================================================================
echo.

REM Check prerequisites
echo [1/7] Checking prerequisites...
where cl >nul 2>nul
if errorlevel 1 (
    echo ERROR: Visual Studio compiler not found
    echo Please run from Developer Command Prompt
    exit /b 1
)

echo   - Visual Studio: OK

REM Clean previous build
echo.
echo [2/7] Cleaning previous build...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
mkdir build
mkdir %OUTPUT_DIR%
mkdir %OUTPUT_DIR%\bin
mkdir %OUTPUT_DIR%\runtime\kernels
mkdir %OUTPUT_DIR%\models
mkdir %OUTPUT_DIR%\config
mkdir %OUTPUT_DIR%\logs\telemetry

echo   - Cleaned

REM Build runtime components
echo.
echo [3/7] Building runtime components...

cd build

REM Build runtime_paths.cpp
echo   - Building runtime_paths.obj
cl /c /O2 /GL /W4 /nologo /DNDEBUG /DWIN32_LEAN_AND_MEAN ^
    /I"%SOURCE_ROOT%\src" ^
    "%SOURCE_ROOT%\src\runtime\runtime_paths.cpp" ^
    /Fo:runtime_paths.obj
if errorlevel 1 goto build_error

REM Build self_test.cpp
echo   - Building self_test.obj
cl /c /O2 /GL /W4 /nologo /DNDEBUG /DWIN32_LEAN_AND_MEAN ^
    /I"%SOURCE_ROOT%\src" ^
    "%SOURCE_ROOT%\src\runtime\self_test.cpp" ^
    /Fo:self_test.obj
if errorlevel 1 goto build_error

REM Build main engine
echo   - Building RawrXD_Engine.exe
cl /O2 /GL /W4 /nologo /DNDEBUG /DWIN32_LEAN_AND_MEAN /Fe:RawrXD_Engine.exe ^
    /I"%SOURCE_ROOT%\src" ^
    "%SOURCE_ROOT%\src\main_runtime.cpp" ^
    runtime_paths.obj ^
    self_test.obj ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB ^
    kernel32.lib user32.lib advapi32.lib ntdll.lib
if errorlevel 1 goto build_error

cd "%SOURCE_ROOT%"

echo   - Build complete

REM Copy binaries
echo.
echo [4/7] Copying binaries...
copy "build\RawrXD_Engine.exe" "%OUTPUT_DIR%\bin\" >nul
copy "build\RawrXD_Server.exe" "%OUTPUT_DIR%\bin\" >nul 2>nul || echo   - RawrXD_Server.exe not found (optional)
copy "build\RawrXD_Benchmark.exe" "%OUTPUT_DIR%\bin\" >nul 2>nul || echo   - RawrXD_Benchmark.exe not found (optional)
echo   - Binaries copied

REM Copy kernel binaries
echo.
echo [5/7] Copying kernel binaries...
if exist "src\kernels\*.bin" (
    copy "src\kernels\*.bin" "%OUTPUT_DIR%\runtime\kernels\" >nul
    echo   - Kernel binaries copied
) else (
    echo   - No kernel binaries found (will be built on first run)
)

REM Create config files
echo.
echo [6/7] Creating configuration files...
(
echo {
echo   "runtime": {
echo     "version": "%VERSION%",
echo     "telemetry_enabled": true,
echo     "log_level": "info",
echo     "deterministic_mode": true
echo   },
echo   "memory": {
echo     "kv_cache_size": "4GB",
echo     "workspace_size": "1GB",
echo     "alignment": 64
echo   },
echo   "compute": {
echo     "avx512_enabled": true,
echo     "flash_attention": true,
echo     "fused_q4": true
echo   }
echo }
) > "%OUTPUT_DIR%\config\sovereign.json"
echo   - sovereign.json created

REM Create README
echo.
echo [7/7] Creating documentation...
(
echo RawrXD Runtime v%VERSION%
echo =======================
echo.
echo Quick Start:
echo   1. Place your GGUF model in the models/ directory
echo   2. Run: bin\RawrXD_Engine.exe --model models\your_model.gguf
echo   3. Run self-test: bin\RawrXD_Engine.exe --self-test
echo.
echo Directory Structure:
echo   bin/         - Executables
echo   runtime/     - Kernel binaries and runtime data
echo   models/      - Place GGUF models here
echo   config/      - Configuration files
echo   logs/        - Runtime logs and telemetry
echo.
echo For support: https://rawrxd.ai/support
) > "%OUTPUT_DIR%\README.txt"
echo   - README.txt created

REM Run dependency audit
echo.
echo ============================================================================
echo Running Dependency Audit (Gate B)
echo ============================================================================
echo.
call scripts\dependency_audit.bat "%OUTPUT_DIR%\bin\RawrXD_Engine.exe"
if errorlevel 1 (
    echo.
    echo WARNING: Dependency audit found issues
    echo Review output above for non-system DLLs
)

REM Package
echo.
echo ============================================================================
echo Creating Distribution Package
echo ============================================================================
echo.

set PACKAGE_NAME=RawrXD_Runtime_v%VERSION%_win64.zip
cd dist
powershell -Command "Compress-Archive -Path 'RawrXD_Runtime_v%VERSION%' -DestinationPath '%PACKAGE_NAME%' -Force"
cd "%SOURCE_ROOT%"

if exist "dist\%PACKAGE_NAME%" (
    echo Package created: dist\%PACKAGE_NAME%
    for %%F in ("dist\%PACKAGE_NAME%") do (
        echo Size: %%~zF bytes
    )
) else (
    echo ERROR: Package creation failed
    exit /b 1
)

REM Summary
echo.
echo ============================================================================
echo Packaging Complete
echo ============================================================================
echo.
echo Output: dist\%PACKAGE_NAME%
echo.
echo Validation Gates:
echo   [A] Clean Machine Test:    Run on target machine
echo   [B] Dependency Audit:      See output above
echo   [C] Self-Test:             Run: RawrXD_Engine.exe --self-test
echo.
echo Next Steps:
echo   1. Copy %PACKAGE_NAME% to clean test machine
echo   2. Extract and run: bin\RawrXD_Engine.exe --self-test
echo   3. Verify all tests pass
echo   4. Test with actual GGUF model
echo.

exit /b 0

:build_error
echo.
echo ERROR: Build failed
cd "%SOURCE_ROOT%"
exit /b 1
