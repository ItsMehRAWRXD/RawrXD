@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD IDE - CLI Integration
echo ============================================
echo.

if "%1"=="" goto usage
if "%1"=="test" goto test
if "%1"=="list" goto list

:compile
set "file=%~1"
set "ext=%~x1"

rem Map file extensions to compilers
if "%ext%"==".c" set "compiler=universal_compiler_fixed.exe"
if "%ext%"==".cpp" set "compiler=universal_compiler_fixed.exe"
if "%ext%"==".asm" set "compiler=universal_compiler_fixed.exe"
if "%ext%"==".py" set "compiler=python_compiler.exe"
if "%ext%"==".sh" set "compiler=bash_compiler_v2.exe"
if "%ext%"==".ps1" set "compiler=powershell_compiler_v2.exe"
if "%ext%"==".java" set "compiler=java_compiler.exe"
if "%ext%"==".cs" set "compiler=csharp_compiler.exe"
if "%ext%"==".js" set "compiler=javascript_compiler.exe"
if "%ext%"==".eon" set "compiler=eon_compiler_v2.exe"

if not defined compiler (
    echo Unknown file extension: %ext%
    echo Supported: .c, .cpp, .asm, .py, .sh, .ps1, .java, .cs, .js, .eon
    exit /b 1
)

echo Compiling %file% with %compiler%...
d:\rawrxd\compilers\fixed_compilers\%compiler% %file%
if %ERRORLEVEL% equ 0 (
    echo Compilation successful!
) else (
    echo Compilation failed with error code %ERRORLEVEL%
)
exit /b %ERRORLEVEL%

:test
echo Running test suite for all compilers...
echo.

set PASS=0
set FAIL=0

echo [1/8] Testing Universal Compiler...
d:\rawrxd\compilers\fixed_compilers\universal_compiler_fixed.exe d:\rawrxd\compilers\test_corpus\test.c
if %ERRORLEVEL% equ 0 (
    echo [PASS] Universal Compiler
    set /a PASS+=1
) else (
    echo [FAIL] Universal Compiler
    set /a FAIL+=1
)

echo.
echo [2/8] Testing EON Compiler...
d:\rawrxd\compilers\fixed_compilers\eon_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.eon
if %ERRORLEVEL% equ 0 (
    echo [PASS] EON Compiler
    set /a PASS+=1
) else (
    echo [FAIL] EON Compiler
    set /a FAIL+=1
)

echo.
echo [3/8] Testing Bash Compiler...
d:\rawrxd\compilers\fixed_compilers\bash_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.sh
if %ERRORLEVEL% equ 0 (
    echo [PASS] Bash Compiler
    set /a PASS+=1
) else (
    echo [FAIL] Bash Compiler
    set /a FAIL+=1
)

echo.
echo [4/8] Testing PowerShell Compiler...
d:\rawrxd\compilers\fixed_compilers\powershell_compiler_v2.exe d:\rawrxd\compilers\test_corpus\test.ps1
if %ERRORLEVEL% equ 0 (
    echo [PASS] PowerShell Compiler
    set /a PASS+=1
) else (
    echo [FAIL] PowerShell Compiler
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

if %FAIL% equ 0 (
    echo All tests passed!
    exit /b 0
) else (
    echo Some tests failed!
    exit /b 1
)

:list
echo Available compilers:
echo   universal_compiler_fixed.exe  - C, C++, Assembly
echo   eon_compiler_v2.exe            - EON (WebAssembly-inspired)
echo   bash_compiler_v2.exe           - Bash scripts
echo   powershell_compiler_v2.exe     - PowerShell scripts
echo   java_compiler.exe              - Java
echo   csharp_compiler.exe            - C#
echo   python_compiler.exe            - Python
echo   javascript_compiler.exe        - JavaScript
exit /b 0

:usage
echo Usage: rawrxd_ide_cli.bat [file]
echo        rawrxd_ide_cli.bat test
echo        rawrxd_ide_cli.bat list
echo.
echo Commands:
echo   file  - Compile a source file (auto-detects compiler by extension)
echo   test  - Run test suite for all compilers
echo   list  - List available compilers
echo.
echo Supported extensions: .c, .cpp, .asm, .py, .sh, .ps1, .java, .cs, .js, .eon
exit /b 1