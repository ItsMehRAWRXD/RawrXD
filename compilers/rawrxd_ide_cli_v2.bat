@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD IDE - CLI v2 (Native Toolchain)
echo ============================================
echo.

set "TOOLCHAIN_DIR=%~dp0native_toolchain"

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

:: Map extensions to compilers
if /I "%EXT%"==".asm" goto compile_asm
if /I "%EXT%"==".c" goto compile_c
if /I "%EXT%"==".cpp" goto compile_c

echo ERROR: Unsupported file extension: %EXT%
echo Supported: .asm, .c, .cpp
echo.
echo For other languages, use the language-specific compiler.
exit /b 1

:compile_asm
echo Detected: Assembly file
echo.
call "%TOOLCHAIN_DIR%\compile_asm.bat" "%FILE%" "%NAME%.exe"
exit /b %ERRORLEVEL%

:compile_c
echo Detected: C/C++ file
echo.
call "%TOOLCHAIN_DIR%\compile_c.bat" "%FILE%" "%NAME%.exe"
exit /b %ERRORLEVEL%

:test
echo Running Native Toolchain Tests...
echo ============================================
echo.

set PASS=0
set FAIL=0

:: Test 1: Assembler
echo [1/3] Testing Native Assembler...
set "TEST_ASM=%TEMP%\test_rawrxd.asm"
echo _start: > "%TEST_ASM%"
echo     mov rax, 42 >> "%TEST_ASM%"
echo     ret >> "%TEST_ASM%"

call "%TOOLCHAIN_DIR%\compile_asm.bat" "%TEST_ASM%" "%TEMP%\test_rawrxd.exe" >nul
if %ERRORLEVEL% equ 0 (
    echo [PASS] Assembler produces valid output
    set /a PASS+=1
) else (
    echo [FAIL] Assembler failed
    set /a FAIL+=1
)

:: Test 2: Linker
echo [2/3] Testing Native Linker...
if exist "%TEMP%\test_rawrxd.exe" (
    echo [PASS] Linker produces valid executable
    set /a PASS+=1
) else (
    echo [FAIL] Linker failed
    set /a FAIL+=1
)

:: Test 3: Execution
echo [3/3] Testing Execution...
if exist "%TEMP%\test_rawrxd.exe" (
    "%TEMP%\test_rawrxd.exe"
    if %ERRORLEVEL% equ 42 (
        echo [PASS] Executable returns correct exit code (42)
        set /a PASS+=1
    ) else (
        echo [FAIL] Executable returned %ERRORLEVEL%, expected 42
        set /a FAIL+=1
    )
) else (
    echo [SKIP] Cannot test execution (no executable)
)

:: Cleanup
if exist "%TEST_ASM%" del "%TEST_ASM%"
if exist "%TEMP%\test_rawrxd.exe" del "%TEMP%\test_rawrxd.exe"
if exist "%TEMP%\test_rawrxd_*.obj" del "%TEMP%\test_rawrxd_*.obj"

echo.
echo ============================================
echo Test Results: %PASS% passed, %FAIL% failed
echo ============================================

if %FAIL% equ 0 (
    echo All tests PASSED! ✅
    exit /b 0
) else (
    echo Some tests FAILED! ❌
    exit /b 1
)

:list
echo Available Compilers:
echo ============================================
echo.
echo Native Toolchain:
echo   compile_asm.bat    - Assembly (.asm) ^→ EXE
echo   compile_c.bat      - C/C++ (.c, .cpp) ^→ EXE
echo.
echo Usage:
echo   rawrxd_ide_cli_v2.bat ^<file^>    - Compile file
echo   rawrxd_ide_cli_v2.bat test        - Run tests
echo   rawrxd_ide_cli_v2.bat list        - Show this list
echo.
exit /b 0

:usage
echo RawrXD IDE - Command Line Interface v2
echo ============================================
echo.
echo USAGE:
echo   rawrxd_ide_cli_v2.bat ^<file^>       Compile a file
echo   rawrxd_ide_cli_v2.bat test          Run test suite
echo   rawrxd_ide_cli_v2.bat list          List compilers
echo   rawrxd_ide_cli_v2.bat help          Show this help
echo.
echo SUPPORTED FILES:
echo   .asm    Assembly files (native toolchain)
echo   .c      C source files
echo   .cpp    C++ source files
echo.
echo EXAMPLES:
echo   rawrxd_ide_cli_v2.bat hello.asm
echo   rawrxd_ide_cli_v2.bat program.c
echo   rawrxd_ide_cli_v2.bat test
echo.
exit /b 0
