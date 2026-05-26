; ==============================================================================
; Sovereign_Dis.asm
; Sovereign Instruction Length Decoder (Minimalist)
; Implementation of "Elite" Suite Component #4
; ==============================================================================

option casemap:none
include Sovereign_Common.inc

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_GetInstructionLength
; Input:  RCX = Pointer to Instruction
; Output: RAX = Length in bytes
; Note: This is a minimalist LDE (Length Disassembler Engine) for x64
; ------------------------------------------------------------------------------
Sovereign_GetInstructionLength PROC
    mov r8, rcx
    xor rax, rax
    
    ; 1. Prefix scan
@next_prefix:
    mov dl, byte ptr [r8]
    cmp dl, 48h                 ; REX
    jb @no_rex
    cmp dl, 4Fh
    ja @no_rex
    inc rax
    inc r8
    jmp @next_prefix
    
@no_rex:
    ; 2. Opcode scan (Minimalist)
    ; This is a complex task for a full disassembler.
    ; For "Sovereign Elite", we assume we are patching standard prologues.
    ; Common: PUSH RBP (55), MOV RBP, RSP (48 89 E5), SUB RSP, XX
    
    mov dl, byte ptr [r8]
    
    ; Typical prologue: push rbp (1 byte)
    cmp dl, 55h
    jne @next1
    mov rax, 1
    ret

@next1:
    ; Typical prologue: sub rsp, imm8 (4 bytes: 48 83 EC XX)
    cmp dl, 48h
    jne @next2
    cmp byte ptr [r8+1], 83h
    jne @next2
    mov rax, 4
    ret

@next2:
    ; Typical prologue: sub rsp, imm32 (7 bytes: 48 81 EC XX XX XX XX)
    cmp dl, 48h
    jne @not_prologue
    cmp byte ptr [r8+1], 81h
    jne @not_prologue
    mov rax, 7
    ret

@not_prologue:
    ; Default fallback for unknown instructions (Safety first: return 1)
    mov rax, 1
    ret
Sovereign_GetInstructionLength ENDP

END
