@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Comprehensive Test Suite
echo ============================================
echo.

set "TEST_DIR=%TEMP%\rawrxd_test_%RANDOM%"
set "PASS=0"
set "FAIL=0"
set "TOTAL=0"

mkdir "%TEST_DIR%" 2>nul

echo Test Directory: %TEST_DIR%
echo.

REM ============================================
echo TEST GROUP 1: Native Toolchain
echo ============================================
echo.

REM Test 1.1: Assembler
echo [1.1] Testing native assembler...
set /a TOTAL+=1
echo _start: > "%TEST_DIR%\test1.asm"
echo     mov rax, 42 >> "%TEST_DIR%\test1.asm"
echo     ret >> "%TEST_DIR%\test1.asm"

d:\rawrxd\compilers\native_toolchain\rawrxd_native_assembler.exe "%TEST_DIR%\test1.asm" "%TEST_DIR%\test1.obj" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEST_DIR%\test1.obj" (
        echo      [PASS] Assembler produces object file
        set /a PASS+=1
    ) else (
        echo      [FAIL] Object file not created
        set /a FAIL+=1
    )
) else (
    echo      [FAIL] Assembler returned error
    set /a FAIL+=1
)

REM Test 1.2: Linker
echo [1.2] Testing native linker...
set /a TOTAL+=1
if exist "%TEST_DIR%\test1.obj" (
    d:\rawrxd\compilers\native_toolchain\rawrxd_native_linker_v2.exe "%TEST_DIR%\test1.obj" /out:"%TEST_DIR%\test1.exe" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        if exist "%TEST_DIR%\test1.exe" (
            echo      [PASS] Linker produces executable
            set /a PASS+=1
        ) else (
            echo      [FAIL] Executable not created
            set /a FAIL+=1
        )
    ) else (
        echo      [FAIL] Linker returned error
        set /a FAIL+=1
    )
) else (
    echo      [SKIP] No object file to link
)

REM Test 1.3: Execution
echo [1.3] Testing execution...
set /a TOTAL+=1
if exist "%TEST_DIR%\test1.exe" (
    "%TEST_DIR%\test1.exe%"
    if %ERRORLEVEL% equ 42 (
        echo      [PASS] Executable returns correct value (42)
        set /a PASS+=1
    ) else (
        echo      [FAIL] Wrong return code: %ERRORLEVEL%
        set /a FAIL+=1
    )
) else (
    echo      [SKIP] No executable to run
)

echo.
REM ============================================
echo TEST GROUP 2: Language Compilers
echo ============================================
echo.

REM Test 2.1: Python Compiler
echo [2.1] Testing Python compiler...
set /a TOTAL+=1
echo print('Hello from Python!') > "%TEST_DIR%\test.py"
d:\rawrxd\compilers\real_compilers\python_compiler_real.exe "%TEST_DIR%\test.py" "%TEST_DIR%\test_py.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEST_DIR%\test_py.exe" (
        echo      [PASS] Python compiler produces executable
        set /a PASS+=1
    ) else (
        echo      [FAIL] Python executable not created
        set /a FAIL+=1
    )
) else (
    echo      [FAIL] Python compiler failed
    set /a FAIL+=1
)

REM Test 2.2: JavaScript Compiler
echo [2.2] Testing JavaScript compiler...
set /a TOTAL+=1
echo console.log('Hello from JS!'); > "%TEST_DIR%\test.js"
d:\rawrxd\compilers\real_compilers\javascript_compiler_real.exe "%TEST_DIR%\test.js" "%TEST_DIR%\test_js.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEST_DIR%\test_js.exe" (
        echo      [PASS] JavaScript compiler produces executable
        set /a PASS+=1
    ) else (
        echo      [FAIL] JavaScript executable not created
        set /a FAIL+=1
    )
) else (
    echo      [FAIL] JavaScript compiler failed
    set /a FAIL+=1
)

REM Test 2.3: EON Compiler
echo [2.3] Testing EON compiler...
set /a TOTAL+=1
echo name = "Test" > "%TEST_DIR%\test.eon"
d:\rawrxd\compilers\real_compilers\eon_compiler_real.exe "%TEST_DIR%\test.eon" "%TEST_DIR%\test_eon.exe" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEST_DIR%\test_eon.exe" (
        echo      [PASS] EON compiler produces executable
        set /a PASS+=1
    ) else (
        echo      [FAIL] EON executable not created
        set /a FAIL+=1
    )
) else (
    echo      [FAIL] EON compiler failed
    set /a FAIL+=1
)

echo.
REM ============================================
echo TEST GROUP 3: CLI Integration
echo ============================================
echo.

REM Test 3.1: CLI Test Command
echo [3.1] Testing CLI test command...
set /a TOTAL+=1
cd d:\rawrxd\compilers
call rawrxd_ide_cli_v3.bat test >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo      [PASS] CLI test command works
    set /a PASS+=1
) else (
    echo      [FAIL] CLI test command failed
    set /a FAIL+=1
)

REM Test 3.2: CLI List Command
echo [3.2] Testing CLI list command...
set /a TOTAL+=1
call rawrxd_ide_cli_v3.bat list >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo      [PASS] CLI list command works
    set /a PASS+=1
) else (
    echo      [FAIL] CLI list command failed
    set /a FAIL+=1
)

echo.
REM ============================================
echo TEST GROUP 4: File Integrity
echo ============================================
echo.

REM Test 4.1: Check executable sizes
echo [4.1] Checking executable sizes...
set /a TOTAL+=1
set "SIZE_OK=1"

for %%F in ("d:\rawrxd\compilers\real_compilers\python_compiler_real.exe" "d:\rawrxd\compilers\real_compilers\javascript_compiler_real.exe" "d:\rawrxd\compilers\real_compilers\bash_compiler_real.exe") do (
    if not exist "%%~F" (
        echo      [WARN] %%~nxF does not exist
        set "SIZE_OK=0"
    )
)

if %SIZE_OK% equ 1 (
    echo      [PASS] All executables exist
    set /a PASS+=1
) else (
    echo      [FAIL] Some executables missing
    set /a FAIL+=1
)

echo.
REM ============================================
echo TEST GROUP 5: Bootstrap
echo ============================================
echo.

REM Test 5.1: Bootstrap Stage 1
echo [5.1] Testing bootstrap stage 1...
set /a TOTAL+=1
if exist "d:\rawrxd\compilers\bootstrap\stage1\rawrxd_native_assembler.exe" (
    echo      [PASS] Bootstrap stage 1 exists
    set /a PASS+=1
) else (
    echo      [FAIL] Bootstrap stage 1 missing
    set /a FAIL+=1
)

REM Test 5.2: Bootstrap Stage 2
echo [5.2] Testing bootstrap stage 2...
set /a TOTAL+=1
if exist "d:\rawrxd\compilers\bootstrap\stage2\self_test.obj" (
    echo      [PASS] Bootstrap stage 2 exists
    set /a PASS+=1
) else (
    echo      [FAIL] Bootstrap stage 2 missing
    set /a FAIL+=1
)

echo.
REM ============================================
echo TEST GROUP 6: Documentation
echo ============================================
echo.

REM Test 6.1: User Manual
echo [6.1] Testing documentation...
set /a TOTAL+=1
if exist "d:\rawrxd\compilers\docs\USER_MANUAL.md" (
    echo      [PASS] User manual exists
    set /a PASS+=1
) else (
    echo      [FAIL] User manual missing
    set /a FAIL+=1
)

REM Test 6.2: Installer Package
echo [6.2] Testing installer package...
set /a TOTAL+=1
if exist "d:\rawrxd\compilers\installer\output\RawrXD-Toolchain-v1.0.zip" (
    echo      [PASS] Installer package exists
    set /a PASS+=1
) else (
    echo      [FAIL] Installer package missing
    set /a FAIL+=1
)

echo.
REM ============================================
echo TEST SUMMARY
echo ============================================
echo.
echo Total Tests:  %TOTAL%
echo Passed:       %PASS%
echo Failed:       %FAIL%
echo.

if %FAIL% equ 0 (
    echo ============================================
    echo ALL TESTS PASSED! ✅
    echo ============================================
    set "EXITCODE=0"
) else (
    echo ============================================
    echo SOME TESTS FAILED! ❌
    echo ============================================
    set "EXITCODE=1"
)

REM Cleanup
rmdir /s /q "%TEST_DIR%" 2>nul

exit /b %EXITCODE%
