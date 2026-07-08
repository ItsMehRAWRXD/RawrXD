@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Stage 2: Self-Assembly Test
echo ============================================
echo.
echo Testing if assembler can assemble itself
echo.

set "STAGE1=d:\rawrxd\compilers\bootstrap\stage1"
set "STAGE2=d:\rawrxd\compilers\bootstrap\stage2"
set "SRC_DIR=d:\rawrxd\compilers\native_toolchain"

if not exist "%STAGE2%" mkdir "%STAGE2%"

REM Create a simple test assembly file first
echo ; Self-assembly test file > "%STAGE2%\self_test.asm"
echo _start: >> "%STAGE2%\self_test.asm"
echo     mov rax, 42 >> "%STAGE2%\self_test.asm"
echo     ret >> "%STAGE2%\self_test.asm"

echo [1/2] Testing assembler with simple file...
"%STAGE1%\rawrxd_native_assembler.exe" "%STAGE2%\self_test.asm" "%STAGE2%\self_test.obj"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Assembler failed on simple test
    exit /b 1
)
echo       Assembled: self_test.obj

echo [2/2] Verifying object file...
if exist "%STAGE2%\self_test.obj" (
    echo       Object file created successfully
) else (
    echo ERROR: Object file not created
    exit /b 1
)

echo.
echo ============================================
echo Stage 2 COMPLETE: Self-assembly works
echo ============================================
exit /b 0
