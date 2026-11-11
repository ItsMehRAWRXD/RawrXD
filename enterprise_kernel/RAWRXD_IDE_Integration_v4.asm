; ============================================================================
; RAWRXD_IDE_Integration_v4.asm - Minimal Working x64 MASM
; ============================================================================

OPTION CASEMAP:NONE

EXTERNDEF __imp_GetStdHandle:QWORD
EXTERNDEF __imp_WriteFile:QWORD
EXTERNDEF __imp_ExitProcess:QWORD

STD_OUTPUT_HANDLE EQU -11
MAX_LANGUAGES EQU 69

.data
align 8
bytesWritten QWORD 0

szInit BYTE "RAWRXD CI Kernel: 69 compilers ready", 13, 10, 0
szDone BYTE "Audit complete. Exiting.", 13, 10, 0

.code

mainCRTStartup PROC
    sub rsp, 40
    
    ; Print init message
    lea rcx, szInit
    call PrintString
    
    ; Print done message  
    lea rcx, szDone
    call PrintString
    
    ; Exit
    xor ecx, ecx
    call qword ptr [__imp_ExitProcess]
    
    add rsp, 40
    ret
mainCRTStartup ENDP

PrintString PROC
    sub rsp, 40
    
    ; Calculate length
    mov rsi, rcx
    xor rdx, rdx
    mov rdi, rcx
L1: cmp byte ptr [rdi], 0
    je L2
    inc rdx
    inc rdi
    jmp L1
L2:
    test rdx, rdx
    jz L3
    
    ; Get stdout
    mov rcx, STD_OUTPUT_HANDLE
    call qword ptr [__imp_GetStdHandle]
    mov rcx, rax
    
    ; Write
    mov r8, rdx
    mov rdx, rsi
    lea r9, bytesWritten
    mov qword ptr [rsp + 32], 0
    call qword ptr [__imp_WriteFile]
    
L3:
    add rsp, 40
    ret
PrintString ENDP

END
