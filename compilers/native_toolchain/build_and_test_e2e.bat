@echo off
REM End-to-end test of native toolchain

echo ============================================
echo RawrXD Native Toolchain - E2E Test
echo ============================================
echo.

set "ASM=d:\rawrxd\compilers\native_toolchain\rawrxd_native_assembler.exe"
set "LINK=d:\rawrxd\compilers\native_toolchain\rawrxd_native_linker.exe"
set "TEST_ASM=test_e2e.asm"
set "TEST_OBJ=test_e2e.obj"
set "TEST_EXE=test_e2e.exe"

echo [1/4] Checking toolchain binaries...
if not exist "%ASM%" (
    echo   ERROR: Assembler not found at %ASM%
    exit /b 1
)
echo   [OK] Assembler found

if not exist "%LINK%" (
    echo   ERROR: Linker not found at %LINK%
    exit /b 1
)
echo   [OK] Linker found

echo.
echo [2/4] Assembling %TEST_ASM%...
"%ASM%" /c %TEST_ASM% %TEST_OBJ% 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   [FAIL] Assembly failed
    exit /b 1
)
echo   [OK] Assembly complete: %TEST_OBJ%

echo.
echo [3/4] Linking %TEST_EXE%...
"%LINK%" %TEST_OBJ% /out:%TEST_EXE% /subsystem:3 /entry:_start 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   [FAIL] Link failed
    exit /b 1
)
echo   [OK] Link complete: %TEST_EXE%

echo.
echo [4/4] Running executable...
%TEST_EXE%
set EXITCODE=%ERRORLEVEL%
echo.
echo   Exit code: %EXITCODE%

if %EXITCODE% EQU 42 (
    echo   [PASS] All tests passed!
) else (
    echo   [FAIL] Expected exit code 42, got %EXITCODE%
)

echo.
echo ============================================
echo E2E Test Complete
echo ============================================
