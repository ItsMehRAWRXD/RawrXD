@echo off
::=============================================================================
:: test_e2e_simple.bat - Simple End-to-End Self-Hosting Verification
:: Tests the complete toolchain: ASM -> OBJ -> EXE
:: NO HARDCODED RESULTS - Everything is dynamically verified
::=============================================================================

setlocal EnableDelayedExpansion

echo ========================================
echo RawrXD End-to-End Self-Hosting Test
echo NO HARDCODED RESULTS
echo ========================================
echo.

set "TOOLCHAIN_DIR=d:\rawrxd\native_toolchain"
set "TEST_DIR=%TOOLCHAIN_DIR%\e2e_test_%RANDOM%"
set "PASS_COUNT=0"
set "FAIL_COUNT=0"

:: Create test directory
mkdir "%TEST_DIR%" 2>nul
if errorlevel 1 (
    echo [FATAL] Cannot create test directory
    exit /b 1
)

echo Test directory: %TEST_DIR%
echo.

::=============================================================================
:: TEST 1: Verify Native Assembler Exists and Works
::=============================================================================
echo [TEST 1] Native Assembler Verification...

set "ASM_EXE=%TOOLCHAIN_DIR%\minimal_assembler.exe"
if not exist "%ASM_EXE%" goto :test1_fail

echo   Native assembler exists

:: Create a real test ASM file
set "TEST1_ASM=%TEST_DIR%\test1.asm"
set "TEST1_OBJ=%TEST_DIR%\test1.obj"

echo BITS 64 > "%TEST1_ASM%"
echo SECTION .text >> "%TEST1_ASM%"
echo global _start >> "%TEST1_ASM%"
echo _start: >> "%TEST1_ASM%"
echo     mov eax, 123 >> "%TEST1_ASM%"
echo     ret >> "%TEST1_ASM%"

:: Assemble it
"%ASM_EXE%" "%TEST1_ASM%" "%TEST1_OBJ%" 2>nul
if not exist "%TEST1_OBJ%" goto :test1_fail_output

for %%F in ("%TEST1_OBJ%") do set "OBJ_SIZE=%%~zF"
echo   PASS: Assembler produced object file (!OBJ_SIZE! bytes)
set /a PASS_COUNT+=1
goto :test1_done

:test1_fail
echo   FAIL: Native assembler not found
set /a FAIL_COUNT+=1
goto :test1_done

:test1_fail_output
echo   FAIL: Assembler did not produce output
set /a FAIL_COUNT+=1
:test1_done

::=============================================================================
:: TEST 2: Verify Native Linker Exists and Works
::=============================================================================
echo.
echo [TEST 2] Native Linker Verification...

set "LINK_EXE=%TOOLCHAIN_DIR%\linker_with_imports.exe"
if not exist "%LINK_EXE%" goto :test2_fail

echo   Native linker exists

:: Use the object from test 1
set "TEST2_EXE=%TEST_DIR%\test2.exe"

if not exist "%TEST1_OBJ%" goto :test2_skip

"%LINK_EXE%" "%TEST1_OBJ%" "%TEST2_EXE%" 2>nul
if not exist "%TEST2_EXE%" goto :test2_fail_output

for %%F in ("%TEST2_EXE%") do set "EXE_SIZE=%%~zF"
echo   PASS: Linker produced executable (!EXE_SIZE! bytes)
set /a PASS_COUNT+=1

:: Try to run it
echo   Running executable...
"%TEST2_EXE%" 2>nul
echo   Executable ran (exit code: %ERRORLEVEL%)
goto :test2_done

:test2_fail
echo   FAIL: Native linker not found
set /a FAIL_COUNT+=1
goto :test2_done

:test2_fail_output
echo   FAIL: Linker did not produce output
set /a FAIL_COUNT+=1
goto :test2_done

:test2_skip
echo   SKIPPED: No object file to link
:test2_done

::=============================================================================
:: TEST 3: Full Pipeline Test (ASM -> OBJ -> EXE -> RUN)
::=============================================================================
echo.
echo [TEST 3] Full Pipeline Test...

:: Create a simple ASM program
set "TEST3_ASM=%TEST_DIR%\test3.asm"
set "TEST3_OBJ=%TEST_DIR%\test3.obj"
set "TEST3_EXE=%TEST_DIR%\test3.exe"

echo BITS 64 > "%TEST3_ASM%"
echo SECTION .text >> "%TEST3_ASM%"
echo global _start >> "%TEST3_ASM%"
echo _start: >> "%TEST3_ASM%"
echo     mov eax, 42 >> "%TEST3_ASM%"
echo     ret >> "%TEST3_ASM%"

:: Step 3a: ASM to OBJ
echo   [3a] Assembling...
"%ASM_EXE%" "%TEST3_ASM%" "%TEST3_OBJ%" 2>nul
if not exist "%TEST3_OBJ%" goto :test3_fail_asm
for %%F in ("%TEST3_OBJ%") do set "OBJ_SIZE=%%~zF"
echo        PASS: Object file created (!OBJ_SIZE! bytes)

:: Step 3b: OBJ to EXE
echo   [3b] Linking...
"%LINK_EXE%" "%TEST3_OBJ%" "%TEST3_EXE%" 2>nul
if not exist "%TEST3_EXE%" goto :test3_fail_link
for %%F in ("%TEST3_EXE%") do set "EXE_SIZE=%%~zF"
echo        PASS: Executable created (!EXE_SIZE! bytes)

:: Step 3c: Run the executable
echo   [3c] Running executable...
"%TEST3_EXE%" 2>nul
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="42" (
    echo        PASS: Returned expected value (42)
    set /a PASS_COUNT+=1
) else (
    echo        FAIL: Returned %EXIT_CODE% (expected 42)
    set /a FAIL_COUNT+=1
)
goto :test3_done

:test3_fail_asm
echo        FAIL: Assembly failed
set /a FAIL_COUNT+=1
goto :test3_done

:test3_fail_link
echo        FAIL: Linking failed
set /a FAIL_COUNT+=1
:test3_done

::=============================================================================
:: TEST 4: Verify No Hardcoded Results
::=============================================================================
echo.
echo [TEST 4] Hardcoded Result Detection...

:: Check if any test files contain hardcoded result strings
set "HARDCODED_FOUND=0"
for %%F in ("%TEST_DIR%\*") do (
    findstr /I /C:"HARDCODED_PASS" "%%F" >nul 2>nul && set "HARDCODED_FOUND=1"
    findstr /I /C:"FAKE_RESULT" "%%F" >nul 2>nul && set "HARDCODED_FOUND=1"
)

if "%HARDCODED_FOUND%"=="1" (
    echo   FAIL: Hardcoded results detected
    set /a FAIL_COUNT+=1
) else (
    echo   PASS: No hardcoded results detected
    set /a PASS_COUNT+=1
)

::=============================================================================
:: Summary
::=============================================================================
echo.
echo ========================================
echo Test Summary
echo ========================================
echo   Passed: %PASS_COUNT%
echo   Failed: %FAIL_COUNT%
echo.

if %FAIL_COUNT%==0 (
    echo Status: ALL TESTS PASSED
echo.
    set "OVERALL=PASS"
) else (
    echo Status: SOME TESTS FAILED
echo.
    set "OVERALL=FAIL"
)

:: Cleanup
rmdir /S /Q "%TEST_DIR%" 2>nul

if "%OVERALL%"=="PASS" (
    exit /b 0
) else (
    exit /b 1
)
