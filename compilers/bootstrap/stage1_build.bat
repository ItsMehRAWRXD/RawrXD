@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Stage 1: Cross-Compilation with MinGW
echo ============================================
echo.
echo Building initial toolchain using MinGW/gcc
echo This creates the seed compiler for self-hosting
echo.

set "SRC_DIR=d:\rawrxd\compilers\native_toolchain"
set "OUT_DIR=d:\rawrxd\compilers\bootstrap\stage1"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [1/3] Building native assembler (seed)...
gcc -O2 -o "%OUT_DIR%\rawrxd_native_assembler.exe" "%SRC_DIR%\rawrxd_native_assembler.c" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build assembler
    exit /b 1
)
echo       Built: %OUT_DIR%\rawrxd_native_assembler.exe

echo [2/3] Building native linker (seed)...
gcc -O2 -o "%OUT_DIR%\rawrxd_native_linker_v2.exe" "%SRC_DIR%\rawrxd_native_linker_v2.c" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build linker
    exit /b 1
)
echo       Built: %OUT_DIR%\rawrxd_native_linker_v2.exe

echo [3/3] Building C compiler (seed)...
gcc -O2 -o "%OUT_DIR%\c_compiler_working.exe" "%SRC_DIR%\c_compiler_working.c" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build C compiler
    exit /b 1
)
echo       Built: %OUT_DIR%\c_compiler_working.exe

echo.
echo ============================================
echo Stage 1 COMPLETE: Seed toolchain built
echo Location: %OUT_DIR%
echo ============================================
exit /b 0
