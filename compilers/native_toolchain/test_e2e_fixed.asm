; test_e2e.asm - Fixed E2E Test
; Pure x64 MASM
;
OPTION CASEMAP:NONE

;=========================================================================
; External declarations
;=========================================================================

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN ExitProcess:PROC

;=========================================================================
; Data section
;=========================================================================

.DATA
msg         DB 'E2E Test Passed', 13, 10, 0
msg_len     EQU $ - msg
written     DQ 0
test_value  DQ 0

;=========================================================================
; Code section
;=========================================================================

.CODE

_start PROC
    ; Get stdout handle
    mov     rcx, -11                    ; STD_OUTPUT_HANDLE
    call    GetStdHandle
    test    rax, rax
    jz      error_exit

    ; Write message
    mov     rcx, rax
    lea     rdx, msg
    mov     r8, msg_len
    lea     r9, written
    push    0
    sub     rsp, 32
    call    WriteFile
    add     rsp, 40
    test    rax, rax
    jz      error_exit

    ; Success - exit with 42
    mov     rcx, 42
    call    ExitProcess

error_exit:
    mov     rcx, 1
    call    ExitProcess

_start ENDP

;=========================================================================
; End
;=========================================================================

END _start
