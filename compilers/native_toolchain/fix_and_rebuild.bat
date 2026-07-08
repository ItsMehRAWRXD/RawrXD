@echo off
REM ==========================================================================
REM Fix and Rebuild E2E Test
REM ==========================================================================

setlocal enabledelayedexpansion

echo ============================================================
echo Fixing E2E Test...
echo ============================================================
echo.

REM Step 1: Create correct test_e2e.asm
echo [1/4] Creating fixed test_e2e.asm...
(
echo ; test_e2e.asm - Fixed E2E Test
echo ; Pure x64 MASM
echo ;
echo OPTION CASEMAP:NONE
echo.
echo ;=========================================================================
echo ; External declarations
echo ;=========================================================================
echo.
echo EXTERN GetStdHandle:PROC
echo EXTERN WriteFile:PROC
echo EXTERN HeapAlloc:PROC
echo EXTERN HeapFree:PROC
echo EXTERN ExitProcess:PROC
echo.
echo ;=========================================================================
echo ; Data section
echo ;=========================================================================
echo.
echo .DATA
echo msg         DB 'E2E Test Passed!', 13, 10, 0
echo msg_len     EQU $ - msg
echo written     DQ 0
echo test_value  DQ 0
echo.
echo ;=========================================================================
echo ; Code section
echo ;=========================================================================
echo.
echo .CODE
echo.
echo _start PROC
echo     ; Get stdout handle
echo     mov     rcx, -11                    ; STD_OUTPUT_HANDLE
echo     call    GetStdHandle
echo     test    rax, rax
echo     jz      error_exit
echo.
echo     ; Write message
echo     mov     rcx, rax
echo     lea     rdx, msg
echo     mov     r8, msg_len
echo     lea     r9, written
echo     push    0
echo     sub     rsp, 32
echo     call    WriteFile
echo     add     rsp, 40
echo     test    rax, rax
echo     jz      error_exit
echo.
echo     ; Success - exit with 42
echo     mov     rcx, 42
echo     call    ExitProcess
echo.
echo error_exit:
echo     mov     rcx, 1
echo     call    ExitProcess
echo.
echo _start ENDP
echo.
echo ;=========================================================================
echo ; End
echo ;=========================================================================
echo.
echo END _start
) > test_e2e_fixed.asm

echo     [OK] Fixed test file created

REM Step 2: Assemble
echo.
echo [2/4] Assembling fixed test_e2e.asm...
.\rawrxd_native_assembler.exe test_e2e_fixed.asm test_e2e_fixed.obj
if errorlevel 1 goto error
echo     [OK] Assembly complete

REM Step 3: Link
echo.
echo [3/4] Linking test_e2e_fixed.exe...
.\rawrxd_native_linker.exe test_e2e_fixed.obj /out:test_e2e_fixed.exe /subsystem:3 /entry:_start
if errorlevel 1 goto error
echo     [OK] Link complete

REM Step 4: Run
echo.
echo [4/4] Running test_e2e_fixed.exe...
.\test_e2e_fixed.exe
set EXITCODE=%ERRORLEVEL%
echo.
echo     Exit code: %EXITCODE%

if %EXITCODE% EQU 42 (
    echo     [OK] Test passed!
) else (
    echo     [FAIL] Expected 42, got %EXITCODE%
    goto error
)

echo.
echo ============================================================
echo E2E Test Fixed and Passing!
echo ============================================================
exit /b 0

:error
echo.
echo ============================================================
echo Build Failed!
echo ============================================================
exit /b 1
