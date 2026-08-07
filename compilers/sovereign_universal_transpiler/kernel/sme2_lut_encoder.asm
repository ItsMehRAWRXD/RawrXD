; ============================================================================
; kernel/sme2_lut_encoder.asm - SME2 LUTI2 & LUTI4 Bitfield Encoders
; Hardware lookup table dequantization for LLM weight expansion
; ============================================================================

option casemap:none

PUBLIC SME2_Encode_LUTI2_S
PUBLIC SME2_Encode_LUTI4_S
PUBLIC SME2_Encode_LUTI2_H
PUBLIC SME2_Encode_LUTI4_H
PUBLIC SME2_Encode_LUTI2_B
PUBLIC SME2_Encode_LUTI4_B
PUBLIC SME2_Encode_LUTI2_D
PUBLIC SME2_Encode_LUTI4_D

.code

; ============================================================================
; SME2_Encode_LUTI2_S: LUTI2 Zd.S, Zn.S, Zm.S[index]
;   2-bit index lookup into 4-entry FP32 table
;   ECX = Zd (Destination, 0..31)
;   EDX = Zn (Table Vector, 0..31)
;   R8D = Zm (Packed 2-bit Index Vector, 0..31)
;   R9D = Segment Index (0..3)
; ============================================================================
SME2_Encode_LUTI2_S PROC
    mov eax, 0C2100000h           ; Base SME2 LUTI2 Single-Precision
    and ecx, 01Fh                 ; Zd (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 01Fh                 ; Zm (bits 16..20)
    and r9d, 003h                 ; Segment Index (bits 10..11)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI2_S ENDP

; ============================================================================
; SME2_Encode_LUTI4_S: LUTI4 Zd.S, {Zn1.S, Zn2.S}, Zm.S[index]
;   4-bit index lookup into 16-entry FP32 table (2 vectors)
;   ECX = Zd (Destination, 0..31)
;   EDX = Zn base (Table 2-tuple base, 0, 2, 4, ... 30) - Must be even!
;   R8D = Zm (Packed 4-bit Index Vector, 0..31)
;   R9D = Segment Index (0..3)
; ============================================================================
SME2_Encode_LUTI4_S PROC
    mov eax, 0C2140000h           ; Base SME2 LUTI4 Single-Precision
    and ecx, 01Fh                 ; Zd (bits 0..4)
    and edx, 01Eh                 ; Zn base (bits 5..9, even index)
    and r8d, 01Fh                 ; Zm (bits 16..20)
    and r9d, 003h                 ; Segment Index (bits 10..11)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI4_S ENDP

; ============================================================================
; SME2_Encode_LUTI2_H: LUTI2 Zd.H, Zn.H, Zm.H[index]
;   2-bit index lookup into 4-entry FP16 table
; ============================================================================
SME2_Encode_LUTI2_H PROC
    mov eax, 0C2104000h           ; Base SME2 LUTI2 Half-Precision
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI2_H ENDP

; ============================================================================
; SME2_Encode_LUTI4_H: LUTI4 Zd.H, {Zn1.H, Zn2.H}, Zm.H[index]
;   4-bit index lookup into 16-entry FP16 table
; ============================================================================
SME2_Encode_LUTI4_H PROC
    mov eax, 0C2144000h           ; Base SME2 LUTI4 Half-Precision
    and ecx, 01Fh
    and edx, 01Eh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI4_H ENDP

; ============================================================================
; SME2_Encode_LUTI2_B: LUTI2 Zd.B, Zn.B, Zm.B[index]
;   2-bit index lookup into 4-entry INT8 table
; ============================================================================
SME2_Encode_LUTI2_B PROC
    mov eax, 0C2108000h           ; Base SME2 LUTI2 Byte
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI2_B ENDP

; ============================================================================
; SME2_Encode_LUTI4_B: LUTI4 Zd.B, {Zn1.B, Zn2.B}, Zm.B[index]
;   4-bit index lookup into 16-entry INT8 table
; ============================================================================
SME2_Encode_LUTI4_B PROC
    mov eax, 0C2148000h           ; Base SME2 LUTI4 Byte
    and ecx, 01Fh
    and edx, 01Eh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI4_B ENDP

; ============================================================================
; SME2_Encode_LUTI2_D: LUTI2 Zd.D, Zn.D, Zm.D[index]
;   2-bit index lookup into 4-entry FP64 table
; ============================================================================
SME2_Encode_LUTI2_D PROC
    mov eax, 0C210C000h           ; Base SME2 LUTI2 Double-Precision
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI2_D ENDP

; ============================================================================
; SME2_Encode_LUTI4_D: LUTI4 Zd.D, {Zn1.D, Zn2.D}, Zm.D[index]
;   4-bit index lookup into 16-entry FP64 table
; ============================================================================
SME2_Encode_LUTI4_D PROC
    mov eax, 0C214C000h           ; Base SME2 LUTI4 Double-Precision
    and ecx, 01Fh
    and edx, 01Eh
    and r8d, 01Fh
    and r9d, 003h

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LUTI4_D ENDP

END
