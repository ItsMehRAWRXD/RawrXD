; ============================================================================
; kernel/sme2_luti_bridge.asm - Lower LUTI Nodes to Machine Binary
; Translates high-level dequantization IR into A64 opcodes
; ============================================================================

option casemap:none

EXTERN SME2_Encode_LDR_ZT0 : PROC
EXTERN SME2_Encode_LUTI2_VG2_S : PROC
EXTERN SME2_Encode_LUTI2_VG4_S : PROC
EXTERN SME2_Encode_LUTI4_VG2_S : PROC
EXTERN SME2_Encode_LUTI4_VG4_S : PROC
EXTERN SME2_Encode_LUTI2_VG2_H : PROC
EXTERN SME2_Encode_LUTI2_VG4_H : PROC
EXTERN SME2_Encode_LUTI4_VG2_H : PROC
EXTERN SME2_Encode_LUTI4_VG4_H : PROC
EXTERN SME2_Encode_LUTI2_VG2_B : PROC
EXTERN SME2_Encode_LUTI2_VG4_B : PROC
EXTERN SME2_Encode_LUTI4_VG2_B : PROC
EXTERN SME2_Encode_LUTI4_VG4_B : PROC
EXTERN SME2_Encode_LUTI2_VG2_D : PROC
EXTERN SME2_Encode_LUTI2_VG4_D : PROC
EXTERN SME2_Encode_LUTI4_VG2_D : PROC
EXTERN SME2_Encode_LUTI4_VG4_D : PROC

PUBLIC Lower_SME2_LUTI_Node

.code

; ============================================================================
; Lower_SME2_LUTI_Node:
;   RCX = LUTIInstructionNode Pointer
;   RDX = Machine Code Buffer Pointer
;   Returns RAX = Updated Machine Code Buffer Pointer
; ============================================================================
Lower_SME2_LUTI_Node PROC frame
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

    mov rsi, rcx                  ; RSI = LUTIInstructionNode
    mov rdi, rdx                  ; RDI = Code Buffer

    movzx eax, word ptr [rsi + 0]  ; Opcode
    mov ecx, dword ptr [rsi + 4]   ; dest_reg / Zd
    mov edx, dword ptr [rsi + 8]   ; src_reg / Zn
    mov r8d, dword ptr [rsi + 20]  ; lut_imm

    ; LUTI Opcode Dispatch
    cmp eax, 0C0h                 ; OP_SME2_LDR_ZT0
    je emit_ldr_zt0

    cmp eax, 0C1h                 ; OP_SME2_LUTI2_VG2_S
    je emit_luti2_vg2_s

    cmp eax, 0C2h                 ; OP_SME2_LUTI2_VG4_S
    je emit_luti2_vg4_s

    cmp eax, 0C3h                 ; OP_SME2_LUTI4_VG2_S
    je emit_luti4_vg2_s

    cmp eax, 0C4h                 ; OP_SME2_LUTI4_VG4_S
    je emit_luti4_vg4_s

    cmp eax, 0C5h                 ; OP_SME2_LUTI2_VG2_H
    je emit_luti2_vg2_h

    cmp eax, 0C6h                 ; OP_SME2_LUTI2_VG4_H
    je emit_luti2_vg4_h

    cmp eax, 0C7h                 ; OP_SME2_LUTI4_VG2_H
    je emit_luti4_vg2_h

    cmp eax, 0C8h                 ; OP_SME2_LUTI4_VG4_H
    je emit_luti4_vg4_h

    cmp eax, 0C9h                 ; OP_SME2_LUTI2_VG2_B
    je emit_luti2_vg2_b

    cmp eax, 0CAh                 ; OP_SME2_LUTI2_VG4_B
    je emit_luti2_vg4_b

    cmp eax, 0CBh                 ; OP_SME2_LUTI4_VG2_B
    je emit_luti4_vg2_b

    cmp eax, 0CCh                 ; OP_SME2_LUTI4_VG4_B
    je emit_luti4_vg4_b

    cmp eax, 0CDh                 ; OP_SME2_LUTI2_VG2_D
    je emit_luti2_vg2_d

    cmp eax, 0CEh                 ; OP_SME2_LUTI2_VG4_D
    je emit_luti2_vg4_d

    cmp eax, 0CFh                 ; OP_SME2_LUTI4_VG2_D
    je emit_luti4_vg2_d

    cmp eax, 0D0h                 ; OP_SME2_LUTI4_VG4_D
    je emit_luti4_vg4_d

    jmp done

emit_ldr_zt0:
    mov ecx, dword ptr [rsi + 12]  ; Base GP (Xn)
    mov edx, dword ptr [rsi + 20]  ; Immediate offset
    call SME2_Encode_LDR_ZT0
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg2_s:
    call SME2_Encode_LUTI2_VG2_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg4_s:
    call SME2_Encode_LUTI2_VG4_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg2_s:
    call SME2_Encode_LUTI4_VG2_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg4_s:
    call SME2_Encode_LUTI4_VG4_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg2_h:
    call SME2_Encode_LUTI2_VG2_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg4_h:
    call SME2_Encode_LUTI2_VG4_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg2_h:
    call SME2_Encode_LUTI4_VG2_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg4_h:
    call SME2_Encode_LUTI4_VG4_H
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg2_b:
    call SME2_Encode_LUTI2_VG2_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg4_b:
    call SME2_Encode_LUTI2_VG4_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg2_b:
    call SME2_Encode_LUTI4_VG2_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg4_b:
    call SME2_Encode_LUTI4_VG4_B
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg2_d:
    call SME2_Encode_LUTI2_VG2_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti2_vg4_d:
    call SME2_Encode_LUTI2_VG4_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg2_d:
    call SME2_Encode_LUTI4_VG2_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_luti4_vg4_d:
    call SME2_Encode_LUTI4_VG4_D
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
Lower_SME2_LUTI_Node ENDP

END
