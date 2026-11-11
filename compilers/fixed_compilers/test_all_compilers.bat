@echo off
echo ============================================
echo Testing All RawrXD Compilers
echo ============================================
echo.

set PASS=0
set FAIL=0

echo [1/8] Testing Universal Compiler v2...
d:\rawrxd\compilers\fixed_compilers\universal_compiler_fixed.exe d:\rawrxd\compilers\test_corpus\test.c
if %ERRORLEVEL% equ 0 (
    echo [PASS] Universal Compiler v2
    set /a PASS+=1
) else (
    echo [FAIL] Universal Compiler v2
    set /a FAIL+=1
)

echo.
echo [2/8] Testing EON Compiler v2...
d:\rawrxd\compilers\fixed_compilers\eon_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.eon
if %ERRORLEVEL% equ 0 (
    echo [PASS] EON Compiler v2
    set /a PASS+=1
) else (
    echo [FAIL] EON Compiler v2
    set /a FAIL+=1
)

echo.
echo [3/8] Testing Bash Compiler v2...
d:\rawrxd\compilers\fixed_compilers\bash_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.sh
if %ERRORLEVEL% equ 0 (
    echo [PASS] Bash Compiler v2
    set /a PASS+=1
) else (
    echo [FAIL] Bash Compiler v2
    set /a FAIL+=1
)

echo.
echo [4/8] Testing PowerShell Compiler v2...
d:\rawrxd\compilers\fixed_compilers\powershell_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.ps1
if %ERRORLEVEL% equ 0 (
    echo [PASS] PowerShell Compiler v2
    set /a PASS+=1
) else (
    echo [FAIL] PowerShell Compiler v2
    set /a FAIL+=1
)

echo.
echo [5/8] Testing Java Compiler...
d:\rawrxd\compilers\fixed_compilers\java_compiler.exe d:\rawrxd\compilers\test_corpus\test.java
if %ERRORLEVEL% equ 0 (
    echo [PASS] Java Compiler
    set /a PASS+=1
) else (
    echo [FAIL] Java Compiler
    set /a FAIL+=1
)

echo.
echo [6/8] Testing C# Compiler...
d:\rawrxd\compilers\fixed_compilers\csharp_compiler.exe d:\rawrxd\compilers\test_corpus\test.cs
if %ERRORLEVEL% equ 0 (
    echo [PASS] C# Compiler
    set /a PASS+=1
) else (
    echo [FAIL] C# Compiler
    set /a FAIL+=1
)

echo.
echo [7/8] Testing Python Compiler...
d:\rawrxd\compilers\fixed_compilers\python_compiler.exe d:\rawrxd\compilers\test_corpus\test.py
if %ERRORLEVEL% equ 0 (
    echo [PASS] Python Compiler
    set /a PASS+=1
) else (
    echo [FAIL] Python Compiler
    set /a FAIL+=1
)

echo.
echo [8/8] Testing JavaScript Compiler...
d:\rawrxd\compilers\fixed_compilers\javascript_compiler.exe d:\rawrxd\compilers\test_corpus\test.js
if %ERRORLEVEL% equ 0 (
    echo [PASS] JavaScript Compiler
    set /a PASS+=1
) else (
    echo [FAIL] JavaScript Compiler
    set /a FAIL+=1
)

echo.
echo ============================================
echo Test Results: %PASS% passed, %FAIL% failed
echo ============================================
echo.

if %FAIL% equ 0 (
    echo All compilers working!
    exit /b 0
) else (
    echo Some compilers failed!
    exit /b 1
)