@echo off
REM ============================================================================
REM RawrXD Native Toolchain - Unified Build Script
REM ============================================================================
REM This script builds all native toolchain components in the correct order.
REM
REM Components:
REM   1. Assembler (rawrxd_native_assembler.exe)
REM   2. Linker (rawrxd_native_linker.exe)
REM   3. Librarian (rawrxd_native_librarian.exe)
REM   4. Resource Compiler (rawrxd_native_rc.exe)
REM   5. Debug Info Generator (rawrxd_native_debug.exe)
REM   6. Import Library Generator (rawrxd_native_implib.exe)
REM   7. Manifest Tool (rawrxd_native_manifest.exe)
REM   8. Runtime Library (rawrxd_native_runtime.lib)
REM ============================================================================

setlocal enabledelayedexpansion

echo ================================================================================
echo RawrXD Native Toolchain Build
echo ================================================================================
echo.

REM Set tool paths
set "GCC=gcc"
set "AR=ar"
set "OBJ_DIR=obj"
set "BIN_DIR=."

REM Create obj directory if it doesn't exist
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

REM Build counter
set BUILD_COUNT=0
set SUCCESS_COUNT=0
set FAIL_COUNT=0

echo [1/8] Building Assembler...
%GCC% -O2 -o rawrxd_native_assembler.exe rawrxd_native_assembler.c 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] rawrxd_native_assembler.exe
    set /a SUCCESS_COUNT+=1
) else (
    echo   [FAIL] rawrxd_native_assembler.exe
    set /a FAIL_COUNT+=1
)
set /a BUILD_COUNT+=1

echo [2/8] Building Linker...
%GCC% -O2 -o rawrxd_native_linker.exe rawrxd_native_linker.c 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] rawrxd_native_linker.exe
    set /a SUCCESS_COUNT+=1
) else (
    echo   [FAIL] rawrxd_native_linker.exe
    set /a FAIL_COUNT+=1
)
set /a BUILD_COUNT+=1

echo [3/8] Building Librarian...
%GCC% -O2 -o rawrxd_native_librarian.exe rawrxd_native_librarian.c 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] rawrxd_native_librarian.exe
    set /a SUCCESS_COUNT+=1
) else (
    echo   [FAIL] rawrxd_native_librarian.exe
    set /a FAIL_COUNT+=1
)
set /a BUILD_COUNT+=1

echo [4/8] Building Resource Compiler...
%GCC% -O2 -o rawrxd_native_rc.exe rawrxd_native_rc.c 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] rawrxd_native_rc.exe
    set /a SUCCESS_COUNT+=1
) else (
    echo   [FAIL] rawrxd_native_rc.exe
    set /a FAIL_COUNT+=1
)
set /a BUILD_COUNT+=1

echo [5/8] Building Debug Info Generator...
if exist rawrxd_native_debug.c (
    %GCC% -O2 -o rawrxd_native_debug.exe rawrxd_native_debug.c 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo   [OK] rawrxd_native_debug.exe
        set /a SUCCESS_COUNT+=1
    ) else (
        echo   [FAIL] rawrxd_native_debug.exe
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] rawrxd_native_debug.c not found
)
set /a BUILD_COUNT+=1

echo [6/8] Building Import Library Generator...
if exist rawrxd_native_implib.c (
    %GCC% -O2 -o rawrxd_native_implib.exe rawrxd_native_implib.c 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo   [OK] rawrxd_native_implib.exe
        set /a SUCCESS_COUNT+=1
    ) else (
        echo   [FAIL] rawrxd_native_implib.exe
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] rawrxd_native_implib.c not found
)
set /a BUILD_COUNT+=1

echo [7/8] Building Manifest Tool...
if exist rawrxd_native_manifest.c (
    %GCC% -O2 -o rawrxd_native_manifest.exe rawrxd_native_manifest.c 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo   [OK] rawrxd_native_manifest.exe
        set /a SUCCESS_COUNT+=1
    ) else (
        echo   [FAIL] rawrxd_native_manifest.exe
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] rawrxd_native_manifest.c not found
)
set /a BUILD_COUNT+=1

echo [8/8] Building Runtime Library...
if exist rawrxd_native_runtime.c (
    %GCC% -c -O2 -o %OBJ_DIR%\runtime.obj rawrxd_native_runtime.c 2>&1
    if %ERRORLEVEL% EQU 0 (
        %AR% rcs rawrxd_native_runtime.lib %OBJ_DIR%\runtime.obj 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo   [OK] rawrxd_native_runtime.lib
            set /a SUCCESS_COUNT+=1
        ) else (
            echo   [FAIL] rawrxd_native_runtime.lib
            set /a FAIL_COUNT+=1
        )
    ) else (
        echo   [FAIL] runtime.obj
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] rawrxd_native_runtime.c not found
)
set /a BUILD_COUNT+=1

echo.
echo ================================================================================
echo Build Summary
echo ================================================================================
echo   Total:   %BUILD_COUNT% components
echo   Success: %SUCCESS_COUNT% components
echo   Failed:  %FAIL_COUNT% components
echo ================================================================================

if %FAIL_COUNT% EQU 0 (
    echo [SUCCESS] All components built successfully!
    exit /b 0
) else (
    echo [WARNING] Some components failed to build
    exit /b 1
)