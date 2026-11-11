; ============================================================================
; kernel/sme2_lut_lowering.asm - SME2 LUTI Dequantization Lowering Bridge
; Translates LUTI IR nodes to binary A64 opcodes for LLM weight expansion
; ============================================================================

option casemap:none

EXTERN SME2_Encode_LUTI2_S : PROC
EXTERN SME2_Encode_LUTI4_S : PROC
EXTERN SME2_Encode_LUTI4_VG2_S : PROC
EXTERN SME2_Encode_LUTI2_H : PROC
EXTERN SME2_Encode_LUTI4_H : PROC
EXTERN SME2_Encode_LUTI2_B : PROC
EXTERN SME2_Encode_LUTI4_B : PROC
EXTERN SME2_Encode_LUTI2_D : PROC
EXTERN SME2_Encode_LUTI4_D : PROC

PUBLIC Lower_SME2_LUT_Node

.code

; ============================================================================
; Lower_SME2_LUT_Node:
;   RCX = LUT IR Node Pointer
;   RDX = Machine Code Buffer Pointer
;   Returns RAX = Updated Buffer Pointer
; ============================================================================
Lower_SME2_LUT_Node PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    mov rsi, rcx                  ; RSI = LUT Node
    mov rdi, rdx                  ; RDI = Output Buffer

    movzx eax, byte ptr [rsi + 0]  ; Opcode
    mov ecx, dword ptr [rsi + 4]   ; Zd / Zd base
    mov edx, dword ptr [rsi + 8]   ; Zn / Zn base
    mov r8d, dword ptr [rsi + 12]  ; Zm (index vector)
    mov r9d, dword ptr [rsi + 16]  ; Segment Index

    ; LUT Opcode Dispatch
    cmp eax, 0C0h                 ; LUT_OP_LUTI2_S
    je emit_luti2_s

    cmp eax, 0C1h                 ; LUT_OP_LUTI4_S
    je emit_luti4_s

    cmp eax, 0C2h                 ; LUT_OP_LUTI4_VG2_S
    je emit_luti4_vg2_s

    cmp eax, 0C3h                 ; LUT_OP_LUTI2_H
    je emit_luti2_h

    cmp eax, 0C4h                 ; LUT_OP_LUTI4_H
    je emit_luti4_h

    cmp eax, 0C5h                 ; LUT_OP_LUTI2_B
    je emit_luti2_b

    cmp eax, 0C6h                 ; LUT_OP_LUTI4_B
    je emit_luti4_b

    cmp eax, 0C7h                 ; LUT_OP_LUTI2_D
    je emit_luti2_d

    cmp eax, 0C8h                 ; LUT_OP_LUTI4_D
    je emit_luti4_d

    jmp done

emit_luti2_s:
    call SME2_Encode_LUTI2_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_s:
    call SME2_Encode_LUTI4_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg2_s:
    call SME2_Encode_LUTI4_VG2_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_h:
    call SME2_Encode_LUTI2_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_h:
    call SME2_Encode_LUTI4_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_b:
    call SME2_Encode_LUTI2_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_b:
    call SME2_Encode_LUTI4_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_d:
    call SME2_Encode_LUTI2_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_d:
    call SME2_Encode_LUTI4_D
    mov dword ptr [rdi], eax
    add rdi, 4

done:
    mov rax, rdi                  ; Return updated buffer pointer
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Lower_SME2_LUT_Node ENDP

END
