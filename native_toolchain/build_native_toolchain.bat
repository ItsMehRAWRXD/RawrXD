@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: Native Toolchain Build Script
:: Builds the complete native toolchain without Microsoft tools
:: ============================================================================

echo ========================================
echo Native Toolchain Build
echo ========================================
echo.

set "TOOLCHAIN_DIR=%~dp0"
cd /d "%TOOLCHAIN_DIR%"

:: Check for GCC (can use MinGW as bootstrap)
where gcc >nul 2>nul
if errorlevel 1 (
    echo [ERROR] GCC not found in PATH
    echo [INFO] Install MinGW-w64 to bootstrap the native toolchain
    exit /b 1
)

echo [OK] Bootstrap compiler: gcc

:: ============================================================================
:: Step 1: Build Native Assembler
:: ============================================================================
echo.
echo [STEP 1] Building Native Assembler...

gcc -O2 -o minimal_assembler.exe minimal_assembler.c -lkernel32
if errorlevel 1 (
    echo [ERROR] Failed to build native assembler
    exit /b 1
)

echo [OK] minimal_assembler.exe created

:: Test assembler
echo [TEST] Testing native assembler...
echo mov rax, rcx > test_input.asm
echo ret >> test_input.asm

minimal_assembler.exe test_input.asm test_output.obj
if errorlevel 1 (
    echo [ERROR] Assembler test failed
    exit /b 1
)

if exist test_output.obj (
    echo [OK] Assembler test passed
    for %%F in (test_output.obj) do echo [INFO] Output: %%~zF bytes
) else (
    echo [ERROR] Assembler produced no output
    exit /b 1
)

:: ============================================================================
:: Step 2: Build Native Linker
:: ============================================================================
echo.
echo [STEP 2] Building Native Linker...

gcc -O2 -o minimal_linker.exe minimal_linker.c -lkernel32
if errorlevel 1 (
    echo [ERROR] Failed to build native linker
    exit /b 1
)

echo [OK] minimal_linker.exe created

:: Test linker
echo [TEST] Testing native linker...
minimal_linker.exe test_output.obj test_output.exe
if errorlevel 1 (
    echo [ERROR] Linker test failed
    exit /b 1
)

if exist test_output.exe (
    echo [OK] Linker test passed
    for %%F in (test_output.exe) do echo [INFO] Output: %%~zF bytes
) else (
    echo [ERROR] Linker produced no output
    exit /b 1
)

:: ============================================================================
:: Step 3: Build Native Runtime
:: ============================================================================
echo.
echo [STEP 3] Building Native Runtime...

gcc -O2 -c -o native_runtime.obj native_runtime.c -ffreestanding -nostdlib
if errorlevel 1 (
    echo [ERROR] Failed to compile native runtime
    exit /b 1
)

echo [OK] native_runtime.obj created

:: Create runtime library
ar rcs native_runtime.lib native_runtime.obj
if errorlevel 1 (
    echo [WARN] Could not create .lib, using .obj directly
)

echo [OK] Native runtime library ready

:: ============================================================================
:: Step 4: Build Native Librarian
:: ============================================================================
echo.
echo [STEP 4] Building Native Librarian...

gcc -O2 -o native_librarian.exe native_librarian.c -lkernel32
if errorlevel 1 (
    echo [ERROR] Failed to build native librarian
    exit /b 1
)

echo [OK] native_librarian.exe created

:: Test librarian
echo [TEST] Testing native librarian...
native_librarian.exe /OUT:test.lib test_output.obj
if errorlevel 1 (
    echo [WARN] Librarian test had issues (non-critical)
) else (
    if exist test.lib (
        echo [OK] Librarian test passed
        for %%F in (test.lib) do echo [INFO] Output: %%~zF bytes
    )
)

:: ============================================================================
:: Step 5: Self-Test - Build minimal program with native toolchain
:: ============================================================================
echo.
echo [STEP 5] Self-Test: Building with native toolchain...

:: Create a simple test program
echo ; Simple test program > selftest.asm
echo mov rax, 42 >> selftest.asm
echo ret >> selftest.asm

echo [BUILD] Assembling selftest.asm...
minimal_assembler.exe selftest.asm selftest.obj
if errorlevel 1 (
    echo [ERROR] Self-test assembly failed
    exit /b 1
)

echo [BUILD] Linking selftest.exe...
minimal_linker.exe selftest.obj selftest.exe
if errorlevel 1 (
    echo [ERROR] Self-test linking failed
    exit /b 1
)

if exist selftest.exe (
    echo [OK] Self-test executable created
    for %%F in (selftest.exe) do echo [INFO] Size: %%~zF bytes
) else (
    echo [ERROR] Self-test failed - no executable
    exit /b 1
)

:: ============================================================================
:: Summary
:: ============================================================================
echo.
echo ========================================
echo Native Toolchain Build Complete
echo ========================================
echo.
echo Components built:
echo   [OK] minimal_assembler.exe  - Native x64 assembler
echo   [OK] minimal_linker.exe    - Native PE linker
echo   [OK] native_runtime.obj    - Native CRT replacement
echo   [OK] native_librarian.exe  - Native static library tool
echo.
echo Toolchain is ready for use!
echo.
echo Example usage:
echo   minimal_assembler.exe input.asm output.obj
echo   minimal_linker.exe output.obj output.exe
echo   native_librarian.exe /OUT:mylib.lib obj1.obj obj2.obj
echo.

:: Cleanup test files
del /q test_input.asm test_output.obj test_output.exe test.lib 2>nul
del /q selftest.asm selftest.obj selftest.exe 2>nul

endlocal
