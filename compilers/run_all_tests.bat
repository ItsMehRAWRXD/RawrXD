@echo off
echo ============================================
echo RawrXD Compiler Test Suite
echo ============================================
echo.

cd /d d:\rawrxd\compilers

set PASS=0
set FAIL=0

echo [TEST 1/4] Universal Compiler v2
echo ----------------------------------------
fixed_compilers\universal_compiler_v2.exe test_corpus\test.c
if %ERRORLEVEL% equ 0 (
    echo [PASS] Universal compiler works
    set /a PASS+=1
) else (
    echo [FAIL] Universal compiler failed
    set /a FAIL+=1
)
echo.

echo [TEST 2/4] EON Compiler v2
echo ----------------------------------------
fixed_compilers\eon_compiler_v2.exe test_corpus\test.eon
if %ERRORLEVEL% equ 0 (
    echo [PASS] EON compiler works
    set /a PASS+=1
) else (
    echo [FAIL] EON compiler failed
    set /a FAIL+=1
)
echo.

echo [TEST 3/4] Bash Compiler v2
echo ----------------------------------------
fixed_compilers\bash_compiler_v2.exe test_corpus\test.sh
if %ERRORLEVEL% equ 0 (
    echo [PASS] Bash compiler works
    set /a PASS+=1
) else (
    echo [FAIL] Bash compiler failed
    set /a FAIL+=1
)
echo.

echo [TEST 4/4] PowerShell Compiler v2
echo ----------------------------------------
fixed_compilers\powershell_compiler_v2.exe test_corpus\test.ps1
if %ERRORLEVEL% equ 0 (
    echo [PASS] PowerShell compiler works
    set /a PASS+=1
) else (
    echo [FAIL] PowerShell compiler failed
    set /a FAIL+=1
)
echo.

echo ============================================
echo Test Results: %PASS% passed, %FAIL% failed
echo ============================================

if %FAIL% gtr 0 exit /b 1
exit /b 0
