; ==============================================================================
; Sovereign_UI_Console.asm
; Elite Console Support - Hex Dumps, Status Bars, and Pattern Visualization
; Pure x64 MASM / Zero Dependencies / Zero IAT
; ==============================================================================

include Sovereign_Common.inc

EXTERNDEF g_ApiTable : SOVEREIGN_API_TABLE

.DATA
    hex_chars db "0123456789ABCDEF"
    hex_buffer db 128 dup(0)
    newline   db 13, 10, 0
    pipe_sep  db " | ", 0
    space     db " ", 0
    hStdOut   dq 0
    written   dq 0

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Print
; Simple wrapper for WriteFile using Zero-IAT table.
; Input: RCX = ASCIIZ String
; ------------------------------------------------------------------------------
PUBLIC Print
Print PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48

    mov rsi, rcx
    test rsi, rsi
    jz @@Done

    ; Get hStdOut if not already cached
    mov rax, [hStdOut]
    test rax, rax
    jnz @@HasHandle
    
    mov rcx, STD_OUTPUT_HANDLE
    call [g_ApiTable.pGetStdHandle]
    mov [hStdOut], rax
@@HasHandle:
    mov rbx, rax ; RBX = hStdOut

    ; Calc length
    xor rdi, rdi
@@LenLoop:
    cmp byte ptr [rsi + rdi], 0
    je @@Write
    inc rdi
    jmp @@LenLoop

@@Write:
    test rdi, rdi
    jz @@Done

    mov rcx, rbx
    mov rdx, rsi
    mov r8, rdi
    lea r9, [written]
    mov qword ptr [rsp + 32], 0
    call [g_ApiTable.pWriteFile]

@@Done:
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Print ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_HexDump
; Input:  RCX = Address, RDX = Length
; ------------------------------------------------------------------------------
PUBLIC Sovereign_HexDump
Sovereign_HexDump PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 80

    mov rsi, rcx            ; Address
    mov rdi, rdx            ; Remaining Length
    
    test rdi, rdi
    jz _Done

_LineLoop:
    test rdi, rdi
    jz _Done

    ; 1. Convert address to hex string in a temp buffer
    push rdi
    push rsi
    mov rcx, rsi
    lea rdx, [rbp-48]
    call _WordToHex
    
    lea rcx, [rbp-48]
    call Print
    
    lea rcx, pipe_sep
    call Print
    
    pop rsi
    pop rdi

    ; (Simplified line loop for now)
    add rsi, 16
    cmp rdi, 16
    jb _EndLine
    sub rdi, 16
    jmp _LineLoop

_EndLine:
    xor rdi, rdi
    jmp _LineLoop

_Done:
    add rsp, 80
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_HexDump ENDP

; --- Internal Helper: _WordToHex ---
; RCX = value, RDX = buffer (must be at least 17 bytes)
_WordToHex PROC
    push rbx
    mov rbx, 16
@@Loop:
    mov rax, rcx
    and rax, 0Fh
    mov al, [hex_chars + rax]
    mov [rdx + rbx - 1], al
    shr rcx, 4
    dec rbx
    jnz @@Loop
    mov byte ptr [rdx + 16], 0
    pop rbx
    ret
_WordToHex ENDP

END
    lea rcx, pipe_sep
    call Print

    ; 2. Print Bytes (16 per line)
    mov rbx, 16
    cmp rbx, rdi
    jle _ProcessLine
    mov rbx, rdi

_ProcessLine:
    push rbx                ; Save bytes in this line
    xor r10, r10            ; Counter
_ByteLoop:
    cmp r10, rbx
    jae _FillSpace
    
    movzx rax, byte ptr [rsi + r10]
    call _ByteToHex
    lea rcx, hex_buffer
    call Print
    lea rcx, space
    call Print
    
    inc r10
    jmp _ByteLoop

_FillSpace:
    ; Align if last line is short
    cmp r10, 16
    jae _PrintASCII
    lea rcx, space
    call Print
    call Print
    call Print
    inc r10
    jmp _FillSpace

_PrintASCII:
    lea rcx, pipe_sep
    call Print
    
    xor r10, r10
_AsciiLoop:
    cmp r10, rbx
    jae _WrapLine
    
    mov al, byte ptr [rsi + r10]
    cmp al, 20h
    jl _NonPrint
    cmp al, 7Eh
    jg _NonPrint
    jmp _PrintIt
_NonPrint:
    mov al, '.'
_PrintIt:
    mov byte ptr [rbp-1], al
    mov byte ptr [rbp], 0
    lea rcx, [rbp-1]
    call Print
    
    inc r10
    jmp _AsciiLoop

_WrapLine:
    lea rcx, newline
    call Print
    
    pop rbx
    add rsi, rbx
    sub rdi, rbx
    jmp _LineLoop

_Done:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_HexDump ENDP

; Internal Helper: Byte to Hex (AL -> hex_buffer)
_ByteToHex PROC
    push rbx
    mov rbx, rax
    shr rax, 4
    and rax, 0Fh
    mov al, [hex_chars + rax]
    mov [hex_buffer], al
    mov rax, rbx
    and rax, 0Fh
    mov al, [hex_chars + rax]
    mov [hex_buffer + 1], al
    mov byte ptr [hex_buffer + 2], 0
    pop rbx
    ret
_ByteToHex ENDP

; Internal Helper: QWord to Hex (RAX -> RDX Buffer)
_WordToHex PROC
    push rbx
    push rdi
    mov rdi, rdx
    mov rbx, rax
    
    mov ecx, 16
_WordLoop:
    mov rax, rbx
    mov edx, ecx
    dec edx
    shl edx, 2
    shr rax, cl ; actually need rbx >> ((ecx-1)*4)
    ; Fix:
    mov rax, rbx
    mov r8, rcx
    dec r8
    shl r8, 2
    mov rcx, r8
    shr rax, cl
    and rax, 0Fh
    mov al, [hex_chars + rax]
    mov [rdi], al
    inc rdi
    
    ; Restore rcx
    mov rcx, r8
    shr rcx, 2
    inc rcx
    
    loop _WordLoop
    mov byte ptr [rdi], 0
    pop rdi
    pop rbx
    ret
_WordToHex ENDP

END
