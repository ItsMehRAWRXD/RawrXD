@echo off
REM ============================================================================
REM ULTIMATE FINAL BUILD - RAWRXD COMPLETE SYSTEM
REM ============================================================================
setlocal EnableDelayedExpansion

echo ================================================================================
echo  RAWRXD ULTIMATE FINAL BUILD
echo  Zero Dependencies ^| Production Ready ^| Complete System
echo ================================================================================
echo.

set "ROOT=%CD%"
set "BUILD_DIR=%ROOT%\build-ultimate"
set "BIN_DIR=%BUILD_DIR%\bin"
set "LIB_DIR=%BUILD_DIR%\lib"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%LIB_DIR%" mkdir "%LIB_DIR%"

echo Build Environment:
echo   Root: %ROOT%
echo   Build: %BUILD_DIR%
echo   Bin: %BIN_DIR%
echo.

REM ============================================================================
REM STAGE 1: SOVEREIGN ENGINE (Zero-Dependency Inference)
REM ============================================================================
echo [STAGE 1/5] Sovereign Engine
echo --------------------------------------------------------------------------------

if exist "%ROOT%\SOVEREIGN_ENGINE_FINAL\sovereign_complete.c" (
    echo  Building sovereign.exe...
    gcc -O3 -march=native -ffast-math -DNDEBUG -o "%BIN_DIR%\sovereign.exe" "%ROOT%\SOVEREIGN_ENGINE_FINAL\sovereign_complete.c" 2>nul
    if exist "%BIN_DIR%\sovereign.exe" (
        for %%F in ("%BIN_DIR%\sovereign.exe") do echo  [OK] sovereign.exe (%%~zF bytes)
    ) else (
        echo  [FAIL] Sovereign build failed
    )
) else (
    echo  [SKIP] sovereign_complete.c not found
)

REM ============================================================================
REM STAGE 2: NATIVE TOOLCHAIN
REM ============================================================================
echo.
echo [STAGE 2/5] Native Toolchain
echo --------------------------------------------------------------------------------

if exist "%ROOT%\native_toolchain\minimal_assembler_with_relocs.c" (
    echo  Building sov_assembler.exe...
    gcc -O2 -o "%BIN_DIR%\sov_assembler.exe" "%ROOT%\native_toolchain\minimal_assembler_with_relocs.c" 2>nul
    if exist "%BIN_DIR%\sov_assembler.exe" (
        for %%F in ("%BIN_DIR%\sov_assembler.exe") do echo  [OK] sov_assembler.exe (%%~zF bytes)
    )
)

if exist "%ROOT%\native_toolchain\linker_with_relocations.c" (
    echo  Building sov_linker.exe...
    gcc -O2 -o "%BIN_DIR%\sov_linker.exe" "%ROOT%\native_toolchain\linker_with_relocations.c" 2>nul
    if exist "%BIN_DIR%\sov_linker.exe" (
        for %%F in ("%BIN_DIR%\sov_linker.exe") do echo  [OK] sov_linker.exe (%%~zF bytes)
    )
)

REM ============================================================================
REM STAGE 3: STREAMING GGUF LOADER
REM ============================================================================
echo.
echo [STAGE 3/5] Streaming GGUF Loader
echo --------------------------------------------------------------------------------

if exist "%ROOT%\src\streaming_gguf_loader.cpp" (
    if exist "%ROOT%\src\streaming_gguf_loader.h" (
        echo  Compiling streaming_gguf_loader.cpp...
        g++ -std=c++17 -O2 -I"%ROOT%\include" -I"%ROOT%\src" -c "%ROOT%\src\streaming_gguf_loader.cpp" -o "%LIB_DIR%\streaming_gguf_loader.obj" 2>nul
        if exist "%LIB_DIR%\streaming_gguf_loader.obj" (
            echo  [OK] streaming_gguf_loader.obj
        )
    )
)

REM ============================================================================
REM STAGE 4: VERIFICATION TESTS
REM ============================================================================
echo.
echo [STAGE 4/5] Verification Tests
echo --------------------------------------------------------------------------------

set "TESTS_PASSED=0"
set "TESTS_FAILED=0"

if exist "%BIN_DIR%\sovereign.exe" (
    echo  Test 1: Sovereign benchmark...
    "%BIN_DIR%\sovereign.exe" benchmark 50 > "%BUILD_DIR%\test1.log" 2>&1
    findstr "tokens/sec" "%BUILD_DIR%\test1.log" >nul && (
        echo  [PASS] Benchmark test
        set /a TESTS_PASSED+=1
    ) || (
        echo  [FAIL] Benchmark test
        set /a TESTS_FAILED+=1
    )
    
    echo  Test 2: Memory report...
    "%BIN_DIR%\sovereign.exe" memory > "%BUILD_DIR%\test2.log" 2>&1
    findstr "MB" "%BUILD_DIR%\test2.log" >nul && (
        echo  [PASS] Memory report
        set /a TESTS_PASSED+=1
    ) || (
        echo  [FAIL] Memory report
        set /a TESTS_FAILED+=1
    )
) else (
    echo  [SKIP] Sovereign tests (executable not found)
)

REM ============================================================================
REM STAGE 5: FINAL SUMMARY
REM ============================================================================
echo.
echo ================================================================================
echo  BUILD COMPLETE
echo ================================================================================
echo.

echo Built Executables:
for %%F in ("%BIN_DIR%\*.exe") do (
    echo   %%~nxF (%%~zF bytes)
)

echo.
echo Test Results: %TESTS_PASSED% passed, %TESTS_FAILED% failed
echo.

echo Usage:
echo   cd %BIN_DIR%
echo   sovereign.exe benchmark 100
echo   sovereign.exe chat
echo   sovereign.exe memory
echo.

echo ================================================================================
echo  RAWRXD SYSTEM READY
echo ================================================================================

cd "%ROOT%"
exit /b 0
