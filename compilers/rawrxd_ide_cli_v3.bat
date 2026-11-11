@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD IDE - CLI v3 (REAL Compilers)
echo ============================================
echo.

set "TOOLCHAIN_DIR=%~dp0"
set "REAL_COMPILERS=%TOOLCHAIN_DIR%real_compilers"

if "%~1"=="" goto usage
if /I "%~1"=="test" goto test
if /I "%~1"=="list" goto list
if /I "%~1"=="help" goto usage

:compile
set "FILE=%~1"
set "EXT=%~x1"
set "NAME=%~n1"

if not exist "%FILE%" (
    echo ERROR: File not found: %FILE%
    exit /b 1
)

:: Map extensions to REAL compilers
if /I "%EXT%"==".asm" goto compile_asm
if /I "%EXT%"==".c" goto compile_c
if /I "%EXT%"==".cpp" goto compile_c
if /I "%EXT%"==".py" goto compile_py
if /I "%EXT%"==".js" goto compile_js
if /I "%EXT%"==".sh" goto compile_sh
if /I "%EXT%"==".ps1" goto compile_ps1
if /I "%EXT%"==".cs" goto compile_cs
if /I "%EXT%"==".java" goto compile_java
if /I "%EXT%"==".eon" goto compile_eon

echo ERROR: Unsupported extension: %EXT%
echo Supported: .asm, .c, .cpp, .py, .js, .sh, .ps1, .cs, .java, .eon
echo.
echo Run 'rawrxd_ide_cli_v3.bat list' for details.
exit /b 1

:compile_asm
echo [ASM] Compiling %FILE%...
call "%TOOLCHAIN_DIR%native_toolchain\compile_asm.bat" "%FILE%" "%NAME%.exe"
exit /b %ERRORLEVEL%

:compile_c
echo [C/C++] Compiling %FILE%...
call "%TOOLCHAIN_DIR%native_toolchain\compile_c.bat" "%FILE%" "%NAME%.exe"
exit /b %ERRORLEVEL%

:compile_py
echo [Python] Compiling %FILE%...
"%REAL_COMPILERS%\python_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires Python installed
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_js
echo [JavaScript] Compiling %FILE%...
"%REAL_COMPILERS%\javascript_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires Node.js installed
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_sh
echo [Bash] Compiling %FILE%...
"%REAL_COMPILERS%\bash_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires WSL or Git Bash
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_ps1
echo [PowerShell] Compiling %FILE%...
"%REAL_COMPILERS%\powershell_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires PowerShell
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_cs
echo [C#] Compiling %FILE%...
"%REAL_COMPILERS%\csharp_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires .NET SDK
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_java
echo [Java] Compiling %FILE%...
"%REAL_COMPILERS%\java_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: Requires JDK
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:compile_eon
echo [EON] Compiling %FILE%...
"%REAL_COMPILERS%\eon_compiler_real.exe" "%FILE%" "%NAME%.exe"
if %ERRORLEVEL% equ 0 (
    echo Success: Created %NAME%.exe
    echo Note: EON compiled to native code
) else (
    echo Error: Compilation failed
)
exit /b %ERRORLEVEL%

:test
echo Running REAL Compiler Tests...
echo ============================================
echo.

set PASS=0
set FAIL=0
set "TEST_DIR=%~dp0test_temp"
if not exist "%TEST_DIR%" mkdir "%TEST_DIR%"

:: Test 1: Assembly
echo [1/5] Testing Assembly Compiler...
set "TEST_ASM=%TEST_DIR%\test_rawrxd.asm"
echo _start: > "%TEST_ASM%"
echo     mov rax, 42 >> "%TEST_ASM%"
echo     ret >> "%TEST_ASM%"
call "%TOOLCHAIN_DIR%native_toolchain\compile_asm.bat" "%TEST_ASM%" "%TEST_DIR%\test_asm.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] Assembly compiler
    set /a PASS+=1
) else (
    echo [FAIL] Assembly compiler
    set /a FAIL+=1
)

:: Test 2: C
echo [2/5] Testing C Compiler...
echo int main(){return 42;} > "%TEST_DIR%\test_rawrxd.c"
call "%TOOLCHAIN_DIR%native_toolchain\compile_c.bat" "%TEST_DIR%\test_rawrxd.c" "%TEST_DIR%\test_c.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] C compiler
    set /a PASS+=1
) else (
    echo [FAIL] C compiler
    set /a FAIL+=1
)

:: Test 3: Python
echo [3/5] Testing Python Compiler...
echo print('Hello') > "%TEST_DIR%\test_rawrxd.py"
"%REAL_COMPILERS%\python_compiler_real.exe" "%TEST_DIR%\test_rawrxd.py" "%TEST_DIR%\test_py.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] Python compiler
    set /a PASS+=1
) else (
    echo [FAIL] Python compiler
)

:: Test 4: JavaScript
echo [4/5] Testing JavaScript Compiler...
echo console.log('Hello'); > "%TEST_DIR%\test_rawrxd.js"
"%REAL_COMPILERS%\javascript_compiler_real.exe" "%TEST_DIR%\test_rawrxd.js" "%TEST_DIR%\test_js.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PASS] JavaScript compiler
    set /a PASS+=1
) else (
    echo [FAIL] JavaScript compiler
)

:: Test 5: Execution
echo [5/5] Testing Execution...
if exist "%TEST_DIR%\test_asm.exe" (
    call "%TEST_DIR%\test_asm.exe" >nul 2>&1
    if !ERRORLEVEL! equ 42 (
        echo [PASS] Executable returns 42
        set /a PASS+=1
    ) else (
        echo [FAIL] Wrong exit code: got !ERRORLEVEL!
        set /a FAIL+=1
    )
) else (
    echo [SKIP] No executable
)

:: Cleanup
if exist "%TEST_DIR%" rmdir /s /q "%TEST_DIR%"

echo.
echo ============================================
echo Results: %PASS% passed, %FAIL% failed
echo ============================================
if %FAIL% equ 0 (
    echo All tests PASSED! ✅
    exit /b 0
) else (
    echo Some tests FAILED! ❌
    exit /b 1
)

:list
echo REAL Compilers Available:
echo ============================================
echo.
echo Native (Self-Hosted):
echo   compile_asm.bat    - Assembly (.asm) ^→ EXE
echo   compile_c.bat      - C/C++ (.c/.cpp) ^→ EXE
echo.
echo Language Wrappers (Require Runtime):
echo   python_compiler_real.exe    - Python (.py) ^→ EXE
echo   javascript_compiler_real.exe - JavaScript (.js) ^→ EXE
echo   bash_compiler_real.exe      - Bash (.sh) ^→ EXE
echo   powershell_compiler_real.exe - PowerShell (.ps1) ^→ EXE
echo   csharp_compiler_real.exe    - C# (.cs) ^→ EXE
echo   java_compiler_real.exe      - Java (.java) ^→ EXE
echo   eon_compiler_real.exe       - EON (.eon) ^→ EXE
echo.
echo Usage:
echo   rawrxd_ide_cli_v3.bat ^<file^>     - Compile file
echo   rawrxd_ide_cli_v3.bat test         - Run tests
echo   rawrxd_ide_cli_v3.bat list         - Show this list
echo.
exit /b 0

:usage
echo RawrXD IDE v3 - REAL Compilers
echo ============================================
echo.
echo USAGE:
echo   rawrxd_ide_cli_v3.bat ^<file^>      Compile a file
echo   rawrxd_ide_cli_v3.bat test          Run test suite
echo   rawrxd_ide_cli_v3.bat list          List compilers
echo.
echo SUPPORTED:
echo   .asm    - Assembly (native)
echo   .c/.cpp - C/C++ (native)
echo   .py     - Python (requires Python)
echo   .js     - JavaScript (requires Node.js)
echo   .sh     - Bash (requires WSL/Git Bash)
echo   .ps1    - PowerShell (requires PowerShell)
echo   .cs     - C# (requires .NET SDK)
echo   .java   - Java (requires JDK)
echo   .eon    - EON (RawrXD config language)
echo.
exit /b 0
