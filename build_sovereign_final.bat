@echo off
REM ============================================================================
REM SOVEREIGN ENGINE FINAL BUILD SCRIPT
REM ============================================================================

setlocal EnableDelayedExpansion

echo ================================================================================
echo  SOVEREIGN ENGINE v3.2.7-FINAL - Complete Build System
echo ================================================================================
echo.

set "ROOT=%CD%"
set "BUILD_DIR=%ROOT%\build"
set "TOOLCHAIN_DIR=%ROOT%\native_toolchain"
set "SOV_DIR=%ROOT%\SOVEREIGN_ENGINE_FINAL"

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\bin" mkdir "%BUILD_DIR%\bin"
if not exist "%BUILD_DIR%\obj" mkdir "%BUILD_DIR%\obj"

echo [1/4] Building Native Toolchain...
echo ================================================================================

REM Build assembler
echo  - Building native assembler...
gcc -O2 -o "%BUILD_DIR%\bin\sov_assembler.exe" "%TOOLCHAIN_DIR%\minimal_assembler_with_relocs.c" 2>nul
if errorlevel 1 (
    echo    ERROR: Assembler build failed
    exit /b 1
)
echo    OK: sov_assembler.exe

REM Build linker
echo  - Building native linker...
gcc -O2 -o "%BUILD_DIR%\bin\sov_linker.exe" "%TOOLCHAIN_DIR%\linker_with_relocations.c" 2>nul
if errorlevel 1 (
    echo    ERROR: Linker build failed
    exit /b 1
)
echo    OK: sov_linker.exe

echo.
echo [2/4] Building Sovereign Engine...
echo ================================================================================

echo  - Building sovereign engine (optimized)...
gcc -O3 -march=native -ffast-math -o "%BUILD_DIR%\bin\sovereign.exe" "%SOV_DIR%\sovereign_complete.c" 2>nul
if errorlevel 1 (
    echo    ERROR: Sovereign build failed
    exit /b 1
)
echo    OK: sovereign.exe

echo.
echo [3/4] Running Integration Tests...
echo ================================================================================

cd "%BUILD_DIR%\bin"

echo  - Test 1: Benchmark 100 tokens...
sovereign.exe benchmark 100 > test1.log 2>&1
findstr "tokens/sec" test1.log >nul && echo    PASS: Benchmark OK || echo    FAIL: Benchmark

echo  - Test 2: Memory report...
sovereign.exe memory > test2.log 2>&1
findstr "MB" test2.log >nul && echo    PASS: Memory OK || echo    FAIL: Memory

echo.
echo [4/4] Build Summary...
echo ================================================================================

echo.
echo Build Artifacts:
echo   %BUILD_DIR%\bin\sov_assembler.exe   (Native x64 assembler)
echo   %BUILD_DIR%\bin\sov_linker.exe       (Native PE linker)
echo   %BUILD_DIR%\bin\sovereign.exe        (Inference engine)
echo.

REM Get file sizes
for %%F in ("%BUILD_DIR%\bin\sov_assembler.exe") do set ASSEMBLER_SIZE=%%~zF
for %%F in ("%BUILD_DIR%\bin\sov_linker.exe") do set LINKER_SIZE=%%~zF
for %%F in ("%BUILD_DIR%\bin\sovereign.exe") do set SOV_SIZE=%%~zF

echo File Sizes:
echo   Assembler:   %ASSEMBLER_SIZE% bytes
echo   Linker:      %LINKER_SIZE% bytes
echo   Sovereign:   %SOV_SIZE% bytes
echo.

echo ================================================================================
echo  BUILD COMPLETE - All components ready
echo ================================================================================
echo.
echo Usage:
echo   sov_assembler.exe ^<input.asm^> ^<output.obj^>
echo   sov_linker.exe ^<input.obj^> ^<output.exe^>
echo   sovereign.exe load ^<model.gguf^>
echo   sovereign.exe infer ^<prompt^>
echo   sovereign.exe benchmark ^<n^>
echo   sovereign.exe chat
echo.

cd "%ROOT%"
exit /b 0
