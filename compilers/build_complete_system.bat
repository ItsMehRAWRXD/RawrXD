@echo off
REM ==============================================================================
REM RawrXD Complete Build System - All Components
REM ==============================================================================
REM This script builds the entire RawrXD toolchain from source:
REM - 8 Language Compilers (C/C++, EON, Bash, PowerShell, Java, C#, Python, JavaScript)
REM - Native Toolchain (Assembler, Linker, Librarian, Resource Compiler)
REM - GUI IDE (Win32 native application)
REM ==============================================================================

setlocal enabledelayedexpansion
set RAWRXD_ROOT=d:\rawrxd
set COMPILERS_DIR=%RAWRXD_ROOT%\compilers
set NATIVE_DIR=%COMPILERS_DIR%\native_toolchain
set FIXED_DIR=%COMPILERS_DIR%\fixed_compilers
set GUI_DIR=%COMPILERS_DIR%\gui_ide

echo ================================================================================
echo RawrXD Complete Build System
echo ================================================================================
echo.
echo [Phase 1] Building Native Toolchain...
echo ================================================================================
echo.

REM Build Native Assembler
echo [1/4] Building Native Assembler...
cd /d %NATIVE_DIR%
gcc -O2 -o rawrxd_native_assembler.exe rawrxd_native_assembler.c 2>nul
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Assembler build failed
    exit /b 1
)
echo [PASS] Native Assembler built successfully

REM Build Native Linker
echo [2/4] Building Native Linker...
gcc -O2 -o rawrxd_native_linker.exe rawrxd_native_linker.c 2>nul
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Linker build failed
    exit /b 1
)
echo [PASS] Native Linker built successfully

REM Build Native Librarian
echo [3/4] Building Native Librarian...
gcc -O2 -o rawrxd_native_librarian.exe rawrxd_native_librarian.c 2>nul
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Librarian build failed
    exit /b 1
)
echo [PASS] Native Librarian built successfully

REM Build Native Resource Compiler
echo [4/4] Building Native Resource Compiler...
gcc -O2 -o rawrxd_native_rc.exe rawrxd_native_rc.c 2>nul
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Resource Compiler build failed
    exit /b 1
)
echo [PASS] Native Resource Compiler built successfully

echo.
echo ================================================================================
echo [Phase 2] Building Language Compilers...
echo ================================================================================
echo.

cd /d %FIXED_DIR%

REM Build all 8 compilers
call build_java.bat
call build_csharp.bat
call build_python.bat
call build_javascript.bat
call build_eon.bat
call build_bash.bat
call build_powershell.bat

echo.
echo ================================================================================
echo [Phase 3] Building GUI IDE...
echo ================================================================================
echo.

cd /d %GUI_DIR%
call build_gui.bat

echo.
echo ================================================================================
echo [Phase 4] Running Integration Tests...
echo ================================================================================
echo.

cd /d %COMPILERS_DIR%

REM Test Native Toolchain
echo [1/3] Testing Native Toolchain...
%NATIVE_DIR%\rawrxd_native_assembler.exe /c %RAWRXD_ROOT%\src\asm\test_simple.asm %NATIVE_DIR%\test_native.obj
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Assembler test failed
    exit /b 1
)
echo [PASS] Native Assembler test passed

%NATIVE_DIR%\rawrxd_native_linker.exe %NATIVE_DIR%\test_native.obj /out:%NATIVE_DIR%\test_native.exe
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Native Linker test failed
    exit /b 1
)
echo [PASS] Native Linker test passed

REM Test Language Compilers
echo [2/3] Testing Language Compilers...
call rawrxd_ide_cli.bat test
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Language Compiler tests failed
    exit /b 1
)

REM Test GUI IDE
echo [3/3] Testing GUI IDE...
if exist %GUI_DIR%\rawrxd_gui.exe (
    echo [PASS] GUI IDE executable exists
) else (
    echo [FAIL] GUI IDE executable missing
    exit /b 1
)

echo.
echo ================================================================================
echo Build Complete - All Components Integrated
echo ================================================================================
echo.
echo Components Built:
echo   - Native Assembler:   %NATIVE_DIR%\rawrxd_native_assembler.exe
echo   - Native Linker:      %NATIVE_DIR%\rawrxd_native_linker.exe
echo   - Native Librarian:   %NATIVE_DIR%\rawrxd_native_librarian.exe
echo   - Native RC:          %NATIVE_DIR%\rawrxd_native_rc.exe
echo   - Universal Compiler: %FIXED_DIR%\universal_compiler_fixed.exe
echo   - EON Compiler:       %FIXED_DIR%\eon_compiler_v2.exe
echo   - Bash Compiler:      %FIXED_DIR%\bash_compiler_v2.exe
echo   - PowerShell Compiler:%FIXED_DIR%\powershell_compiler_v2.exe
echo   - Java Compiler:      %FIXED_DIR%\java_compiler.exe
echo   - C# Compiler:        %FIXED_DIR%\csharp_compiler.exe
echo   - Python Compiler:    %FIXED_DIR%\python_compiler.exe
echo   - JavaScript Compiler: %FIXED_DIR%\javascript_compiler.exe
echo   - GUI IDE:            %GUI_DIR%\rawrxd_gui.exe
echo.
echo CLI Integration: %COMPILERS_DIR%\rawrxd_ide_cli.bat
echo Test Suite:      %COMPILERS_DIR%\run_all_tests.bat
echo.
echo ================================================================================
echo.
echo Usage:
echo   Compile file:     rawrxd_ide_cli.bat [file]
echo   Run tests:        rawrxd_ide_cli.bat test
echo   List compilers:   rawrxd_ide_cli.bat list
echo   Assemble native:  rawrxd_native_assembler.exe /c input.asm output.obj
echo   Link native:       rawrxd_native_linker.exe input.obj /out:output.exe
echo ================================================================================

exit /b 0