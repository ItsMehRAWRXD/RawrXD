; =============================================================================
; SwarmV29_Test_Entry.asm - Minimal Test Entry Point
; =============================================================================
; Provides entry point for linking SwarmV29
; Date: 2026-07-14
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            PUBLICS
; =============================================================================
PUBLIC mainCRTStartup

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

; =============================================================================
;                            DATA
; =============================================================================
.data

ALIGN 16
SuccessMessage BYTE "SwarmV29 AZDO Integration Test - SUCCESS", 0Dh, 0Ah, 0
SuccessLen QWORD $ - SuccessMessage

ALIGN 16
ReturnValue QWORD 0
BytesWritten QWORD 0
StdHandle QWORD 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; mainCRTStartup
; Minimal CRT startup for console app
; =============================================================================
mainCRTStartup PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Get stdout handle
    sub rsp, 32             ; shadow space
    mov rcx, -11            ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov QWORD PTR [StdHandle], rax
    
    ; Write success message
    lea rcx, SuccessMessage
    mov rdx, SuccessLen
    lea r8, BytesWritten
    mov r9, QWORD PTR [StdHandle]
    
    ; WriteFile(hStdOut, msg, len, &bytesWritten, NULL)
    push 0                  ; lpOverlapped = NULL
    mov r9, r8              ; lpNumberOfBytesWritten
    mov r8, rdx             ; nNumberOfBytesToWrite
    mov rdx, rcx            ; lpBuffer
    mov rcx, QWORD PTR [StdHandle]  ; hFile
    sub rsp, 32
    call WriteFile
    add rsp, 40
    
    ; Exit with success
    mov rcx, 0
    call ExitProcess
    
    ; Never reached
    xor eax, eax
    
    SWARMV29_ABI_EPILOG
mainCRTStartup ENDP

END