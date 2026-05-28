; ==============================================================================
; Module: Sovereign_Console.asm
; Pure x64 MASM - Win64 ABI Compliant - No C Runtime Dependencies
; ==============================================================================

PUBLIC Sovereign_Print

.DATA
    ; Placeholders for pre-resolved kernel32 function pointers
    extern g_hStdOut:QWORD
    extern g_pWriteFile:QWORD

.CODE
ALIGN 16

; ------------------------------------------------------------------------------
; Sovereign_Print
; Input: RCX = Pointer to null-terminated string
; ------------------------------------------------------------------------------
Sovereign_Print PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h                    ; 32 bytes shadow space + 16 bytes local/alignment

    mov [rbp+10h], rcx              ; Save string pointer

    ; 1. Calculate String Length (Inline strlen)
    xor rdx, rdx                    ; RDX = length counter
CalcLength:
    mov al, byte ptr [rcx + rdx]
    test al, al
    jz LengthFound
    inc rdx
    jmp CalcLength
LengthFound:

    ; 2. Call WriteFile(hStdOut, buffer, length, &bytesWritten, NULL)
    mov r8, rdx                     ; nNumberOfBytesToWrite
    mov rdx, [rbp+10h]              ; lpBuffer
    mov rcx, qword ptr [g_hStdOut]  ; hFile (Resolved via PEB/Syscall)
    lea r9, [rbp-8h]                ; lpNumberOfBytesWritten (Local variable)
    mov qword ptr [rsp+20h], 0      ; lpOverlapped = NULL

    call qword ptr [g_pWriteFile]   ; Execute resolved API call

    add rsp, 40h
    pop rbp
    ret
Sovereign_Print ENDP

; ----------------------------------------------------------------------------
; Probe: Write a single ASCII character (in CL) followed by newline to stdout
; ----------------------------------------------------------------------------
PUBLIC Probe
Probe PROC
    sub rsp, 40
    mov byte ptr [rsp+32], cl
    mov byte ptr [rsp+33], 10
    
    mov rcx, [g_hStdOut]
    lea rdx, [rsp+32]
    mov r8, 2
    lea r9, [rsp+34]
    mov qword ptr [rsp+32], 0
    call [g_pWriteFile]
    
    add rsp, 40
    ret
Probe ENDP

END
