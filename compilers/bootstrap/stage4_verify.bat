@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Stage 4: Verification
echo ============================================
echo.
echo Verifying self-built toolchain
echo.

set "STAGE1=d:\rawrxd\compilers\bootstrap\stage1"
set "STAGE3=d:\rawrxd\compilers\bootstrap\stage3"

echo [1/3] Testing self-built assembler...
if not exist "%STAGE3%\rawrxd_native_assembler.exe" (
    echo ERROR: Self-built assembler not found
    exit /b 1
)

echo ; Verification test > "%TEMP%\verify_test.asm"
echo _start: >> "%TEMP%\verify_test.asm"
echo     mov rax, 123 >> "%TEMP%\verify_test.asm"
echo     ret >> "%TEMP%\verify_test.asm"

"%STAGE3%\rawrxd_native_assembler.exe" "%TEMP%\verify_test.asm" "%TEMP%\verify_test.obj" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Self-built assembler failed
    exit /b 1
)
echo       Self-built assembler: WORKING

echo [2/3] Testing self-built linker...
if not exist "%STAGE3%\rawrxd_native_linker_v2.exe" (
    echo ERROR: Self-built linker not found
    exit /b 1
)

"%STAGE3%\rawrxd_native_linker_v2.exe" "%TEMP%\verify_test.obj" /out:"%TEMP%\verify_test.exe" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Self-built linker failed
    exit /b 1
)
echo       Self-built linker: WORKING

echo [3/3] Running verification executable...
if exist "%TEMP%\verify_test.exe" (
    "%TEMP%\verify_test.exe%"
    set EXITCODE=%ERRORLEVEL%
    if !EXITCODE! equ 123 (
        echo       Verification executable: CORRECT (returned 123)
    ) else (
        echo       Verification executable: WRONG (returned !EXITCODE!, expected 123)
        exit /b 1
    )
) else (
    echo ERROR: Verification executable not created
    exit /b 1
)

echo.
echo ============================================
echo Stage 4 COMPLETE: Verification PASSED
echo Self-hosting: SUCCESS
echo ============================================
exit /b 0
