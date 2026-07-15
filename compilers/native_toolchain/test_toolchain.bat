@echo off
REM ============================================================================
REM RawrXD Native Toolchain - Integration Test Script
REM ============================================================================
REM This script validates the complete toolchain pipeline from assembly to
REM executable, testing all components together.
REM ============================================================================

setlocal enabledelayedexpansion

echo ================================================================================
echo RawrXD Native Toolchain - Integration Test
echo ================================================================================
echo.

set "PASS_COUNT=0"
set "FAIL_COUNT=0"
set "TEST_COUNT=0"

REM Test 1: Assembler - Simple Assembly
echo [TEST 1] Assembler - Simple Assembly
set /a TEST_COUNT+=1
echo .text > test_simple.asm
echo main: >> test_simple.asm
echo     mov rax, 42 >> test_simple.asm
echo     ret >> test_simple.asm
echo. >> test_simple.asm

rawrxd_native_assembler.exe /c test_simple.asm test_simple.obj 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist test_simple.obj (
        echo   [PASS] Simple assembly compiled
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] Object file not created
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [FAIL] Assembler returned error
    set /a FAIL_COUNT+=1
)

REM Test 2: Assembler - Kernel Assembly
echo [TEST 2] Assembler - Kernel Assembly
set /a TEST_COUNT+=1
if exist "d:\rawrxd\src\asm\RawrCodex_Multi_Reference_v2.asm" (
    rawrxd_native_assembler.exe /c "d:\rawrxd\src\asm\RawrCodex_Multi_Reference_v2.asm" test_kernel.obj 2>&1 | findstr /C:"Success" >nul
    if %ERRORLEVEL% EQU 0 (
        echo   [PASS] Kernel assembly compiled
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] Kernel assembly failed
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] Kernel file not found
    set /a TEST_COUNT-=1
)

REM Test 3: Linker - Simple Executable
echo [TEST 3] Linker - Simple Executable
set /a TEST_COUNT+=1
rawrxd_native_linker.exe test_simple.obj /out:test_simple.exe 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist test_simple.exe (
        echo   [PASS] Simple executable linked
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] Executable not created
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [FAIL] Linker returned error
    set /a FAIL_COUNT+=1
)

REM Test 4: Linker - Kernel Executable
echo [TEST 4] Linker - Kernel Executable
set /a TEST_COUNT+=1
if exist test_kernel.obj (
    rawrxd_native_linker.exe test_kernel.obj /out:test_kernel.exe 2>&1 | findstr /C:"Success" >nul
    if %ERRORLEVEL% EQU 0 (
        if exist test_kernel.exe (
            echo   [PASS] Kernel executable linked
            set /a PASS_COUNT+=1
        ) else (
            echo   [FAIL] Kernel executable not created
            set /a FAIL_COUNT+=1
        )
    ) else (
        echo   [FAIL] Kernel linker failed
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] Kernel object not found
    set /a TEST_COUNT-=1
)

REM Test 5: PE Validation
echo [TEST 5] PE Validation
set /a TEST_COUNT+=1
if exist test_simple.exe (
    powershell -Command "$b=[IO.File]::ReadAllBytes('test_simple.exe'); if($b[0] -eq 0x4D -and $b[1] -eq 0x5A) { exit 0 } else { exit 1 }" 2>nul
    if %ERRORLEVEL% EQU 0 (
        echo   [PASS] PE header valid (MZ signature)
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] Invalid PE header
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] No executable to validate
    set /a TEST_COUNT-=1
)

REM Test 6: Librarian - Create Library
echo [TEST 6] Librarian - Create Library
set /a TEST_COUNT+=1
if exist test_simple.obj (
    rawrxd_native_librarian.exe /out:test_library.lib test_simple.obj 2>&1
    if %ERRORLEVEL% EQU 0 (
        if exist test_library.lib (
            echo   [PASS] Library created
            set /a PASS_COUNT+=1
        ) else (
            echo   [FAIL] Library not created
            set /a FAIL_COUNT+=1
        )
    ) else (
        echo   [FAIL] Librarian returned error
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] No object file for library
    set /a TEST_COUNT-=1
)

REM Test 7: Resource Compiler (if RC file exists)
echo [TEST 7] Resource Compiler
set /a TEST_COUNT+=1
if exist test.rc (
    rawrxd_native_rc.exe test.rc test.res 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo   [PASS] Resource compiled
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] Resource compilation failed
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [SKIP] No resource file to test
    set /a TEST_COUNT-=1
)

REM Test 8: End-to-End Pipeline
echo [TEST 8] End-to-End Pipeline
set /a TEST_COUNT+=1
echo .text > test_e2e.asm
echo _start: >> test_e2e.asm
echo     mov rax, 1 >> test_e2e.asm
echo     mov rbx, 2 >> test_e2e.asm
echo     add rax, rbx >> test_e2e.asm
echo     ret >> test_e2e.asm

rawrxd_native_assembler.exe /c test_e2e.asm test_e2e.obj 2>&1 >nul
if %ERRORLEVEL% NEQ 0 (
    echo   [FAIL] Assembly stage failed
    set /a FAIL_COUNT+=1
    goto :test_summary
)

rawrxd_native_linker.exe test_e2e.obj /out:test_e2e.exe 2>&1 >nul
if %ERRORLEVEL% NEQ 0 (
    echo   [FAIL] Link stage failed
    set /a FAIL_COUNT+=1
    goto :test_summary
)

if exist test_e2e.exe (
    powershell -Command "$b=[IO.File]::ReadAllBytes('test_e2e.exe'); if($b[0] -eq 0x4D -and $b[1] -eq 0x5A) { exit 0 } else { exit 1 }" 2>nul
    if %ERRORLEVEL% EQU 0 (
        echo   [PASS] End-to-end pipeline successful
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] End-to-end PE validation failed
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [FAIL] End-to-end executable not created
    set /a FAIL_COUNT+=1
)

:test_summary
echo.
echo ================================================================================
echo Test Summary
echo ================================================================================
echo   Total:   %TEST_COUNT% tests
echo   Passed:  %PASS_COUNT% tests
echo   Failed:  %FAIL_COUNT% tests
echo ================================================================================

REM Cleanup
if exist test_simple.asm del test_simple.asm
if exist test_simple.obj del test_simple.obj
if exist test_simple.exe del test_simple.exe
if exist test_e2e.asm del test_e2e.asm
if exist test_e2e.obj del test_e2e.obj
if exist test_e2e.exe del test_e2e.exe
if exist test_library.lib del test_library.lib

if %FAIL_COUNT% EQU 0 (
    echo [SUCCESS] All tests passed!
    exit /b 0
) else (
    echo [WARNING] Some tests failed
    exit /b 1
)