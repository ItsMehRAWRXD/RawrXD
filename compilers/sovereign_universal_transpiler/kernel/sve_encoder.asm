; ============================================================================
; kernel/sve_encoder.asm - ARM64 Scalable Vector Extension (SVE) Encoder
; ============================================================================

option casemap:none

PUBLIC SVE_Encode_WHILELT_S
PUBLIC SVE_Encode_WHILELT_D
PUBLIC SVE_Encode_LD1W_Reg
PUBLIC SVE_Encode_ST1W_Reg
PUBLIC SVE_Encode_LD1D_Reg
PUBLIC SVE_Encode_ST1D_Reg
PUBLIC SVE_Encode_FADD_S
PUBLIC SVE_Encode_FSUB_S
PUBLIC SVE_Encode_FMUL_S
PUBLIC SVE_Encode_FADD_D
PUBLIC SVE_Encode_FMUL_D
PUBLIC SVE_Encode_INCW
PUBLIC SVE_Encode_INCD
PUBLIC SVE_Encode_PTRUE
PUBLIC SVE_Encode_PFALSE
PUBLIC SVE_Encode_BRKA
PUBLIC SVE_Encode_BRKB
PUBLIC SVE_Encode_CNT
PUBLIC SVE_Encode_DUP_Z_R

.code

; ============================================================================
; SVE_Encode_WHILELT_S: WHILELT Pd.S, Xn, Xm (32-bit scalar comparison)
;   ECX = Pd (Predicate Target 0..15)
;   EDX = Xn (Scalar Index Register)
;   R8D = Xm (Scalar Limit Register)
; ============================================================================
SVE_Encode_WHILELT_S PROC
    ; Base Template: 0x25603000 (sf=1, size=10 [32-bit], lt condition)
    mov eax, 025603000h
    and ecx, 00Fh                 ; Pd field (bits 0..3)
    and edx, 01Fh                 ; Rn field (bits 5..9)
    and r8d, 01Fh                 ; Rm field (bits 16..20)

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE_Encode_WHILELT_S ENDP

; ============================================================================
; SVE_Encode_WHILELT_D: WHILELT Pd.D, Xn, Xm (64-bit scalar comparison)
;   ECX = Pd, EDX = Xn, R8D = Xm
; ============================================================================
SVE_Encode_WHILELT_D PROC
    ; Base Template: 0x25E03000 (sf=1, size=11 [64-bit])
    mov eax, 025E03000h
    and ecx, 00Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE_Encode_WHILELT_D ENDP

; ============================================================================
; SVE_Encode_LD1W_Reg: LD1W { Zt.S }, Pg/Z, [Xn, Xm, LSL #2]
;   ECX = Zt (Vector Target Register 0..31)
;   EDX = Xn (Base GP Pointer)
;   R8D = Xm (Index Register)
;   R9D = Pg (Governing Predicate Register 0..7)
; ============================================================================
SVE_Encode_LD1W_Reg PROC
    ; Base Template: 0xA5404000 (size=10 [32-bit], scalar reg offset)
    mov eax, 0A5404000h
    and ecx, 01Fh                 ; Zt field (bits 0..4)
    and edx, 01Fh                 ; Xn field (bits 5..9)
    and r8d, 01Fh                 ; Xm field (bits 16..20)
    and r9d, 007h                 ; Pg field (bits 10..12)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_LD1W_Reg ENDP

; ============================================================================
; SVE_Encode_ST1W_Reg: ST1W { Zt.S }, Pg, [Xn, Xm, LSL #2]
;   ECX = Zt, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE_Encode_ST1W_Reg PROC
    ; Base Template: 0xE5404000
    mov eax, 0E5404000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_ST1W_Reg ENDP

; ============================================================================
; SVE_Encode_LD1D_Reg: LD1D { Zt.D }, Pg/Z, [Xn, Xm, LSL #3]
;   ECX = Zt, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE_Encode_LD1D_Reg PROC
    ; Base Template: 0xA5C04000 (size=11 [64-bit])
    mov eax, 0A5C04000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_LD1D_Reg ENDP

; ============================================================================
; SVE_Encode_ST1D_Reg: ST1D { Zt.D }, Pg, [Xn, Xm, LSL #3]
;   ECX = Zt, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE_Encode_ST1D_Reg PROC
    ; Base Template: 0xE5C04000
    mov eax, 0E5C04000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_ST1D_Reg ENDP

; ============================================================================
; SVE_Encode_FADD_S: FADD Zd.S, Pg/M, Zn.S, Zm.S (Predicated Merging Float Add)
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
; ============================================================================
SVE_Encode_FADD_S PROC
    ; Base Template: 0x65208000
    mov eax, 065208000h
    and ecx, 01Fh                 ; Zd (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 01Fh                 ; Zm (bits 16..20)
    and r9d, 007h                 ; Pg (bits 10..12)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_FADD_S ENDP

; ============================================================================
; SVE_Encode_FSUB_S: FSUB Zd.S, Pg/M, Zn.S, Zm.S
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
; ============================================================================
SVE_Encode_FSUB_S PROC
    ; Base Template: 0x65208000 with bit 10 set for subtract
    mov eax, 065208400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_FSUB_S ENDP

; ============================================================================
; SVE_Encode_FMUL_S: FMUL Zd.S, Pg/M, Zn.S, Zm.S
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
; ============================================================================
SVE_Encode_FMUL_S PROC
    ; Base Template: 0x65208800
    mov eax, 065208800h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_FMUL_S ENDP

; ============================================================================
; SVE_Encode_FADD_D: FADD Zd.D, Pg/M, Zn.D, Zm.D (64-bit float)
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
; ============================================================================
SVE_Encode_FADD_D PROC
    ; Base Template: 0x65E08000 (size=11 for double)
    mov eax, 065E08000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_FADD_D ENDP

; ============================================================================
; SVE_Encode_FMUL_D: FMUL Zd.D, Pg/M, Zn.D, Zm.D
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
; ============================================================================
SVE_Encode_FMUL_D PROC
    ; Base Template: 0x65E08800
    mov eax, 065E08800h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE_Encode_FMUL_D ENDP

; ============================================================================
; SVE_Encode_INCW: INCW Xn (Increment by count of 32-bit elements in VL)
;   ECX = Xn (0..31)
; ============================================================================
SVE_Encode_INCW PROC
    ; Base Template: 0x04E0E000 (pattern=ALL, imm4=0)
    mov eax, 004E0E000h
    and ecx, 01Fh
    mov edx, ecx
    shl edx, 5
    or eax, ecx
    or eax, edx
    ret
SVE_Encode_INCW ENDP

; ============================================================================
; SVE_Encode_INCD: INCD Xn (Increment by count of 64-bit elements in VL)
;   ECX = Xn
; ============================================================================
SVE_Encode_INCD PROC
    ; Base Template: 0x04F0E000 (size=11 for 64-bit)
    mov eax, 004F0E000h
    and ecx, 01Fh
    mov edx, ecx
    shl edx, 5
    or eax, ecx
    or eax, edx
    ret
SVE_Encode_INCD ENDP

; ============================================================================
; SVE_Encode_PTRUE: PTRUE Pd.S (Set all predicate elements to true)
;   ECX = Pd (0..15)
; ============================================================================
SVE_Encode_PTRUE PROC
    ; Base Template: 0x2518E000 (size=10 for S)
    mov eax, 02518E000h
    and ecx, 00Fh
    or eax, ecx
    ret
SVE_Encode_PTRUE ENDP

; ============================================================================
; SVE_Encode_PFALSE: PFALSE Pd (Set all predicate elements to false)
;   ECX = Pd
; ============================================================================
SVE_Encode_PFALSE PROC
    ; Base Template: 0x2518E010
    mov eax, 02518E010h
    and ecx, 00Fh
    or eax, ecx
    ret
SVE_Encode_PFALSE ENDP

; ============================================================================
; SVE_Encode_BRKA: BRKA Pd.B, Pg/Z, Pn.B (Break after first active)
;   ECX = Pd, EDX = Pg, R8D = Pn
; ============================================================================
SVE_Encode_BRKA PROC
    ; Base Template: 0x05003000
    mov eax, 005003000h
    and ecx, 00Fh
    and edx, 007h
    and r8d, 00Fh
    
    shl edx, 10
    shl r8d, 5
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE_Encode_BRKA ENDP

; ============================================================================
; SVE_Encode_BRKB: BRKB Pd.B, Pg/Z, Pn.B (Break before first active)
;   ECX = Pd, EDX = Pg, R8D = Pn
; ============================================================================
SVE_Encode_BRKB PROC
    ; Base Template: 0x05003400
    mov eax, 005003400h
    and ecx, 00Fh
    and edx, 007h
    and r8d, 00Fh
    
    shl edx, 10
    shl r8d, 5
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE_Encode_BRKB ENDP

; ============================================================================
; SVE_Encode_CNT: CNT Xd, Pg (Count active elements in predicate)
;   ECX = Xd, EDX = Pg
; ============================================================================
SVE_Encode_CNT PROC
    ; Base Template: 0x25208000
    mov eax, 025208000h
    and ecx, 01Fh
    and edx, 007h
    
    shl edx, 10
    or eax, ecx
    or eax, edx
    ret
SVE_Encode_CNT ENDP

; ============================================================================
; SVE_Encode_DUP_Z_R: DUP Zd.S, Pg/M, Rn (Broadcast scalar to vector)
;   ECX = Zd, EDX = Pg, R8D = Rn
; ============================================================================
SVE_Encode_DUP_Z_R PROC
    ; Base Template: 0x05203800
    mov eax, 005203800h
    and ecx, 01Fh
    and edx, 007h
    and r8d, 01Fh
    
    shl edx, 10
    shl r8d, 5
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE_Encode_DUP_Z_R ENDP

END
