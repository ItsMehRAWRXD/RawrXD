; ============================================================================
; kernel/sme2_lowering.asm - SME2 Multi-Vector IR Lowering Bridge
; Translates SME2 IR nodes to binary A64 opcodes
; ============================================================================

option casemap:none

EXTERN SME2_Encode_FMOPA_VG2_S : PROC
EXTERN SME2_Encode_FMOPA_VG4_S : PROC
EXTERN SME2_Encode_FMOPA_VG2_D : PROC
EXTERN SME2_Encode_FMOPA_VG4_D : PROC
EXTERN SME2_Encode_LD1W_VG2 : PROC
EXTERN SME2_Encode_LD1W_VG4 : PROC
EXTERN SME2_Encode_ST1W_VG2 : PROC
EXTERN SME2_Encode_ST1W_VG4 : PROC
EXTERN SME2_Encode_LD1D_VG2 : PROC
EXTERN SME2_Encode_LD1D_VG4 : PROC
EXTERN SME2_Encode_ST1D_VG2 : PROC
EXTERN SME2_Encode_ST1D_VG4 : PROC
EXTERN SME2_Encode_ZERO_VG2 : PROC
EXTERN SME2_Encode_ZERO_VG4 : PROC
EXTERN SME2_Encode_SMSTART_VG4 : PROC
EXTERN SME2_Encode_SMSTOP_VG4 : PROC

PUBLIC Lower_SME2_Node

.code

; ============================================================================
; Lower_SME2_Node:
;   RCX = SME2 IR Node Pointer
;   RDX = Machine Code Buffer Pointer
;   Returns RAX = Updated Buffer Pointer
; ============================================================================
Lower_SME2_Node PROC frame
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
    sub rsp, 40h                  ; Shadow space + stack args
    .allocstack 40h
    .endprolog

    mov rsi, rcx                  ; RSI = IR Node
    mov rdi, rdx                  ; RDI = Output Buffer

    movzx eax, byte ptr [rsi + 0]  ; Opcode
    mov ecx, dword ptr [rsi + 4]   ; TileIdx / Zt base
    mov edx, dword ptr [rsi + 8]   ; Src1Reg / Zn / Xn
    mov r8d, dword ptr [rsi + 12]  ; Src2Reg / Zm / Xm
    mov r9d, dword ptr [rsi + 16]  ; Pred1Reg / Pn / Pg

    ; SME2 Opcode Dispatch
    cmp eax, 0B0h                 ; SME2_OP_SMSTART
    je emit_smstart

    cmp eax, 0B1h                 ; SME2_OP_SMSTOP
    je emit_smstop

    cmp eax, 0B2h                 ; SME2_OP_ZERO_VG2
    je emit_zero_vg2

    cmp eax, 0B3h                 ; SME2_OP_ZERO_VG4
    je emit_zero_vg4

    cmp eax, 0B4h                 ; SME2_OP_LD1W_VG2
    je emit_ld1w_vg2

    cmp eax, 0B5h                 ; SME2_OP_LD1W_VG4
    je emit_ld1w_vg4

    cmp eax, 0B6h                 ; SME2_OP_ST1W_VG2
    je emit_st1w_vg2

    cmp eax, 0B7h                 ; SME2_OP_ST1W_VG4
    je emit_st1w_vg4

    cmp eax, 0B8h                 ; SME2_OP_FMOPA_VG2_S
    je emit_fmopa_vg2_s

    cmp eax, 0B9h                 ; SME2_OP_FMOPA_VG4_S
    je emit_fmopa_vg4_s

    cmp eax, 0BAh                 ; SME2_OP_FMOPA_VG2_D
    je emit_fmopa_vg2_d

    cmp eax, 0BBh                 ; SME2_OP_FMOPA_VG4_D
    je emit_fmopa_vg4_d

    cmp eax, 0BCh                 ; SME2_OP_LD1D_VG2
    je emit_ld1d_vg2

    cmp eax, 0BDh                 ; SME2_OP_LD1D_VG4
    je emit_ld1d_vg4

    cmp eax, 0BEh                 ; SME2_OP_ST1D_VG2
    je emit_st1d_vg2

    cmp eax, 0BFh                 ; SME2_OP_ST1D_VG4
    je emit_st1d_vg4

    jmp done

emit_smstart:
    call SME2_Encode_SMSTART_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_smstop:
    call SME2_Encode_SMSTOP_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_zero_vg2:
    call SME2_Encode_ZERO_VG2
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_zero_vg4:
    call SME2_Encode_ZERO_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_ld1w_vg2:
    call SME2_Encode_LD1W_VG2
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_ld1w_vg4:
    call SME2_Encode_LD1W_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_st1w_vg2:
    call SME2_Encode_ST1W_VG2
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_st1w_vg4:
    call SME2_Encode_ST1W_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_fmopa_vg2_s:
    mov eax, dword ptr [rsi + 20]  ; Load Pm from node
    mov dword ptr [rsp + 28h], eax ; Stack arg 5
    call SME2_Encode_FMOPA_VG2_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_fmopa_vg4_s:
    mov eax, dword ptr [rsi + 20]  ; Load Pm from node
    mov dword ptr [rsp + 28h], eax ; Stack arg 5
    call SME2_Encode_FMOPA_VG4_S
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_fmopa_vg2_d:
    mov eax, dword ptr [rsi + 20]
    mov dword ptr [rsp + 28h], eax
    call SME2_Encode_FMOPA_VG2_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_fmopa_vg4_d:
    mov eax, dword ptr [rsi + 20]
    mov dword ptr [rsp + 28h], eax
    call SME2_Encode_FMOPA_VG4_D
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_ld1d_vg2:
    call SME2_Encode_LD1D_VG2
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_ld1d_vg4:
    call SME2_Encode_LD1D_VG4
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_st1d_vg2:
    call SME2_Encode_ST1D_VG2
    mov dword ptr [rdi], eax
    add rdi, 4
    jmp done

emit_st1d_vg4:
    call SME2_Encode_ST1D_VG4
    mov dword ptr [rdi], eax
    add rdi, 4

done:
    mov rax, rdi                  ; Return updated buffer pointer
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Lower_SME2_Node ENDP

END
