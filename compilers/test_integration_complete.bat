@echo off
REM ==============================================================================
REM RawrXD Unified Integration - Complete System Test
REM ==============================================================================
REM Tests all components working together:
REM - Native toolchain (assembler, linker)
REM - Language compilers (8 languages)
REM - CLI integration
REM - End-to-end compilation pipeline
REM ==============================================================================

setlocal enabledelayedexpansion
set RAWRXD_ROOT=d:\rawrxd
set COMPILERS_DIR=%RAWRXD_ROOT%\compilers
set NATIVE_DIR=%COMPILERS_DIR%\native_toolchain
set FIXED_DIR=%COMPILERS_DIR%\fixed_compilers
set TEST_CORPUS=%COMPILERS_DIR%\test_corpus

echo ================================================================================
echo RawrXD Unified Integration Test
echo ================================================================================
echo.

set PASS=0
set FAIL=0

echo [1] Native Toolchain Integration
echo ================================================================================
echo.

echo [1.1] Testing Native Assembler with kernel file...
%NATIVE_DIR%\rawrxd_native_assembler.exe /c %RAWRXD_ROOT%\src\asm\test_simple.asm %NATIVE_DIR%\integration_test.obj
if %ERRORLEVEL% equ 0 (
    echo [PASS] Native Assembler processed test file
    set /a PASS+=1
) else (
    echo [FAIL] Native Assembler failed
    set /a FAIL+=1
)

echo.
echo [1.2] Testing Native Linker...
%NATIVE_DIR%\rawrxd_native_linker.exe %NATIVE_DIR%\integration_test.obj /out:%NATIVE_DIR%\integration_test.exe
if %ERRORLEVEL% equ 0 (
    echo [PASS] Native Linker created executable
    set /a PASS+=1
) else (
    echo [FAIL] Native Linker failed
    set /a FAIL+=1
)

echo.
echo [2] Language Compiler Integration
echo ================================================================================
echo.

echo [2.1] Testing Universal Compiler (C/C++/ASM)...
%FIXED_DIR%\universal_compiler_fixed.exe %TEST_CORPUS%\test.c
if %ERRORLEVEL% equ 0 (
    echo [PASS] Universal Compiler processed C file
    set /a PASS+=1
) else (
    echo [FAIL] Universal Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.2] Testing EON Compiler...
%FIXED_DIR%\eon_compiler_v2.exe %TEST_CORPUS%\test.eon
if %ERRORLEVEL% equ 0 (
    echo [PASS] EON Compiler processed EON file
    set /a PASS+=1
) else (
    echo [FAIL] EON Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.3] Testing Bash Compiler...
%FIXED_DIR%\bash_compiler_v2.exe %TEST_CORPUS%\test.sh
if %ERRORLEVEL% equ 0 (
    echo [PASS] Bash Compiler processed shell script
    set /a PASS+=1
) else (
    echo [FAIL] Bash Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.4] Testing PowerShell Compiler...
%FIXED_DIR%\powershell_compiler_v2.exe %TEST_CORPUS%\test.ps1
if %ERRORLEVEL% equ 0 (
    echo [PASS] PowerShell Compiler processed PS1 file
    set /a PASS+=1
) else (
    echo [FAIL] PowerShell Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.5] Testing Java Compiler...
%FIXED_DIR%\java_compiler.exe %TEST_CORPUS%\test.java
if %ERRORLEVEL% equ 0 (
    echo [PASS] Java Compiler processed Java file
    set /a PASS+=1
) else (
    echo [FAIL] Java Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.6] Testing C# Compiler...
%FIXED_DIR%\csharp_compiler.exe %TEST_CORPUS%\test.cs
if %ERRORLEVEL% equ 0 (
    echo [PASS] C# Compiler processed C# file
    set /a PASS+=1
) else (
    echo [FAIL] C# Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.7] Testing Python Compiler...
%FIXED_DIR%\python_compiler.exe %TEST_CORPUS%\test.py
if %ERRORLEVEL% equ 0 (
    echo [PASS] Python Compiler processed Python file
    set /a PASS+=1
) else (
    echo [FAIL] Python Compiler failed
    set /a FAIL+=1
)

echo.
echo [2.8] Testing JavaScript Compiler...
%FIXED_DIR%\javascript_compiler.exe %TEST_CORPUS%\test.js
if %ERRORLEVEL% equ 0 (
    echo [PASS] JavaScript Compiler processed JS file
    set /a PASS+=1
) else (
    echo [FAIL] JavaScript Compiler failed
    set /a FAIL+=1
)

echo.
echo [3] CLI Integration Test
echo ================================================================================
echo.

echo [3.1] Testing CLI auto-detection...
%COMPILERS_DIR%\rawrxd_ide_cli.bat %TEST_CORPUS%\test.c >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] CLI auto-detected C file
    set /a PASS+=1
) else (
    echo [FAIL] CLI auto-detection failed
    set /a FAIL+=1
)

echo.
echo [3.2] Testing CLI test suite...
%COMPILERS_DIR%\rawrxd_ide_cli.bat test >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] CLI test suite passed
    set /a PASS+=1
) else (
    echo [FAIL] CLI test suite failed
    set /a FAIL+=1
)

echo.
echo [4] End-to-End Pipeline Test
echo ================================================================================
echo.

echo [4.1] Creating test assembly file...
echo ; Test assembly for native toolchain > %NATIVE_DIR%\pipeline_test.asm
echo bits 64 >> %NATIVE_DIR%\pipeline_test.asm
echo default rel >> %NATIVE_DIR%\pipeline_test.asm
echo section .text >> %NATIVE_DIR%\pipeline_test.asm
echo global main >> %NATIVE_DIR%\pipeline_test.asm
echo main: >> %NATIVE_DIR%\pipeline_test.asm
echo     mov rax, 42 >> %NATIVE_DIR%\pipeline_test.asm
echo     ret >> %NATIVE_DIR%\pipeline_test.asm

echo [4.2] Assembling with native assembler...
%NATIVE_DIR%\rawrxd_native_assembler.exe /c %NATIVE_DIR%\pipeline_test.asm %NATIVE_DIR%\pipeline_test.obj
if %ERRORLEVEL% equ 0 (
    echo [PASS] Native assembler created object file
    set /a PASS+=1
) else (
    echo [FAIL] Native assembler failed
    set /a FAIL+=1
)

echo.
echo [4.3] Linking with native linker...
%NATIVE_DIR%\rawrxd_native_linker.exe %NATIVE_DIR%\pipeline_test.obj /out:%NATIVE_DIR%\pipeline_test.exe
if %ERRORLEVEL% equ 0 (
    echo [PASS] Native linker created executable
    set /a PASS+=1
) else (
    echo [FAIL] Native linker failed
    set /a FAIL+=1
)

echo.
echo [5] GUI IDE Verification
echo ================================================================================
echo.

if exist %COMPILERS_DIR%\gui_ide\rawrxd_gui.exe (
    echo [PASS] GUI IDE executable exists
    set /a PASS+=1
) else (
    echo [FAIL] GUI IDE executable missing
    set /a FAIL+=1
)

echo.
echo ================================================================================
echo Integration Test Results: %PASS% passed, %FAIL% failed
echo ================================================================================
echo.

if %FAIL% equ 0 (
    echo SUCCESS: All components integrated successfully!
    echo.
    echo The RawrXD system is now fully operational:
    echo   - Native toolchain: Assembler, Linker, Librarian, RC
    echo   - Language compilers: 8 languages supported
    echo   - CLI integration: Auto-detection and test suite
    echo   - GUI IDE: Win32 native application
    echo   - End-to-end pipeline: Assembly to executable
    exit /b 0
) else (
    echo FAILURE: Some components failed integration tests
    exit /b 1
)