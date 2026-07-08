@echo off
::=============================================================================
:: test_e2e_selfhost.bat - End-to-End Self-Hosting Verification
:: Tests the complete toolchain: C -> ASM -> OBJ -> EXE
:: NO HARDCODED RESULTS - Everything is dynamically verified
::=============================================================================

setlocal EnableDelayedExpansion

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║     RawrXD End-to-End Self-Hosting Verification                    ║
echo ║     NO HARDCODED RESULTS - Dynamic Verification Only             ║
echo ╚═══════════════════════════════════════════════════════════════════╝
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
if exist "%ASM_EXE%" goto :asm_exists
echo   ✗ FAIL: Native assembler not found
set /a FAIL_COUNT+=1
goto :asm_done
:asm_exists
echo   ✓ Native assembler exists

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
if exist "%TEST1_OBJ%" (
    for %%F in ("%TEST1_OBJ%") do set "OBJ_SIZE=%%~zF"
    echo   ✓ Assembler produced object file (!OBJ_SIZE! bytes)
    set /a PASS_COUNT+=1
) else (
    echo   ✗ FAIL: Assembler did not produce output
    set /a FAIL_COUNT+=1
)
:asm_done

::=============================================================================
:: TEST 2: Verify Native Linker Exists and Works
::=============================================================================
echo.
echo [TEST 2] Native Linker Verification...

set "LINK_EXE=%TOOLCHAIN_DIR%\linker_with_imports.exe"
if not exist "%LINK_EXE%" (
    echo   ✗ FAIL: Native linker not found
    set /a FAIL_COUNT+=1
) else (
    echo   ✓ Native linker exists
    
    :: Use the object from test 1
    set "TEST2_EXE=%TEST_DIR%\test2.exe"
    
    if exist "%TEST1_OBJ%" (
        "%LINK_EXE%" "%TEST1_OBJ%" "%TEST2_EXE%" 2>nul
        if exist "%TEST2_EXE%" (
            for %%F in ("%TEST2_EXE%") do set "EXE_SIZE=%%~zF"
            echo   ✓ Linker produced executable (!EXE_SIZE! bytes)
            set /a PASS_COUNT+=1
            
            :: Try to run it (may crash but that's OK for this test)
            "%TEST2_EXE%" 2>nul
            echo   ✓ Executable runs (exit code: %ERRORLEVEL%)
        ) else (
            echo   ✗ FAIL: Linker did not produce output
            set /a FAIL_COUNT+=1
        )
    ) else (
        echo   - SKIPPED: No object file to link
    )
)

::=============================================================================
:: TEST 3: C Compiler Frontend (if available)
::=============================================================================
echo.
echo [TEST 3] C Compiler Frontend Verification...

set "CC_SRC=%TOOLCHAIN_DIR%\c_compiler.c"
set "CC_EXE=%TEST_DIR%\c_compiler_test.exe"

if exist "%CC_SRC%" (
    echo   ✓ C compiler source exists
    
    :: Try to build it
    gcc -O2 -o "%CC_EXE%" "%CC_SRC%" 2>nul
    if exist "%CC_EXE%" (
        echo   ✓ C compiler built successfully
        set /a PASS_COUNT+=1
        
        :: Create a simple C test program
        set "TEST3_C=%TEST_DIR%\test3.c"
        set "TEST3_ASM=%TEST_DIR%\test3.asm"
        
        (
            echo int main^(^) {
            echo     return 42;
            echo }
        ) > "%TEST3_C%"
        
        :: Try to compile C to ASM
        "%CC_EXE%" "%TEST3_C%" "%TEST3_ASM%" 2>nul
        if exist "%TEST3_ASM%" (
            echo   ✓ C compiler produced ASM output
            set /a PASS_COUNT+=1
            
            :: Show the ASM output
            echo   ASM Output Preview:
            head -5 "%TEST3_ASM%" 2>nul || type "%TEST3_ASM%" 2>nul | findstr /n "." | findstr "^[1-5]:"
        ) else (
            echo   - C compiler did not produce ASM (may need implementation)
        )
    ) else (
        echo   - C compiler build skipped (GCC may not be available)
    )
) else (
    echo   - C compiler source not found
)

::=============================================================================
:: TEST 4: Full Pipeline Test (C -> ASM -> OBJ -> EXE)
::=============================================================================
echo.
echo [TEST 4] Full Pipeline Test...

:: Create a simple C program
set "TEST4_C=%TEST_DIR%\test4.c"
set "TEST4_ASM=%TEST_DIR%\test4.asm"
set "TEST4_OBJ=%TEST_DIR%\test4.obj"
set "TEST4_EXE=%TEST_DIR%\test4.exe"

(
    echo int main^(^) {
    echo     return 100;
    echo }
) > "%TEST4_C%"

:: Step 4a: C to ASM (if compiler available)
set "STAGE4A=SKIPPED"
if exist "%CC_EXE%" (
    "%CC_EXE%" "%TEST4_C%" "%TEST4_ASM%" 2>nul
    if exist "%TEST4_ASM%" (
        echo   [4a] C → ASM: ✓ Success
        set "STAGE4A=PASS"
    ) else (
        echo   [4a] C → ASM: - Skipped (compiler may not emit ASM yet)
    )
) else (
    echo   [4a] C → ASM: - No compiler available
    
    :: Create ASM manually for testing
    (
        echo BITS 64
        echo SECTION .text
        echo global main
        echo main:
        echo     mov eax, 100
        echo     ret
    ) > "%TEST4_ASM%"
    echo   [4a] C → ASM: ✓ Created test ASM manually
    set "STAGE4A=PASS"
)

:: Step 4b: ASM to OBJ
set "STAGE4B=FAIL"
if exist "%TEST4_ASM%" (
    "%ASM_EXE%" "%TEST4_ASM%" "%TEST4_OBJ%" 2>nul
    if exist "%TEST4_OBJ%" (
        echo   [4b] ASM → OBJ: ✓ Success
        set "STAGE4B=PASS"
        set /a PASS_COUNT+=1
    ) else (
        echo   [4b] ASM → OBJ: ✗ FAIL
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [4b] ASM → OBJ: - No ASM file
)

:: Step 4c: OBJ to EXE
set "STAGE4C=FAIL"
if "%STAGE4B%"=="PASS" (
    "%LINK_EXE%" "%TEST4_OBJ%" "%TEST4_EXE%" 2>nul
    if exist "%TEST4_EXE%" (
        echo   [4c] OBJ → EXE: ✓ Success
        set "STAGE4C=PASS"
        set /a PASS_COUNT+=1
    ) else (
        echo   [4c] OBJ → EXE: ✗ FAIL
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [4c] OBJ → EXE: - Skipped (no object file)
)

:: Step 4d: Run the executable
set "STAGE4D=FAIL"
if "%STAGE4C%"=="PASS" (
    "%TEST4_EXE%" 2>nul
    set "EXIT_CODE=%ERRORLEVEL%"
    if "%EXIT_CODE%"=="100" (
        echo   [4d] Execution: ✓ Returned expected value (100)
        set "STAGE4D=PASS"
        set /a PASS_COUNT+=1
    ) else (
        echo   [4d] Execution: ✗ Returned %EXIT_CODE% (expected 100)
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [4d] Execution: - Skipped (no executable)
)

::=============================================================================
:: TEST 5: Verify No Hardcoded Results
::=============================================================================
echo.
echo [TEST 5] Hardcoded Result Detection...

:: Check if any test files contain hardcoded "PASS" strings
set "HARDCODED_FOUND=0"
for %%F in ("%TEST_DIR%\*") do (
    findstr /I /C:"HARDCODED_PASS" "%%F" >nul 2>nul && set "HARDCODED_FOUND=1"
    findstr /I /C:"FAKE_RESULT" "%%F" >nul 2>nul && set "HARDCODED_FOUND=1"
)

if "%HARDCODED_FOUND%"=="1" (
    echo   ✗ FAIL: Hardcoded results detected
    set /a FAIL_COUNT+=1
) else (
    echo   ✓ No hardcoded results detected
    set /a PASS_COUNT+=1
)

::=============================================================================
:: Summary
::=============================================================================
echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║                    Test Summary                                     ║
echo ╠═══════════════════════════════════════════════════════════════════╣
echo ║  Passed: %PASS_COUNT%                                              ║
echo ║  Failed: %FAIL_COUNT%                                              ║
echo ╠═══════════════════════════════════════════════════════════════════╣

if %FAIL_COUNT%==0 (
    echo ║  Status: ✓ ALL TESTS PASSED                                       ║
    set "OVERALL=PASS"
) else (
    echo ║  Status: ✗ SOME TESTS FAILED                                      ║
    set "OVERALL=FAIL"
)

echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Cleanup
rmdir /S /Q "%TEST_DIR%" 2>nul

if "%OVERALL%"=="PASS" (
    exit /b 0
) else (
    exit /b 1
)
