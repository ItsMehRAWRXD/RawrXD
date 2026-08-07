; ============================================================================
; kernel/sme2_luti_encoder.asm - ARM64 SME2 LUTI2/LUTI4 Encoders
; ZT0 table register load, 2-bit and 4-bit lookup table dequantization
; ============================================================================

option casemap:none

PUBLIC SME2_Encode_LDR_ZT0
PUBLIC SME2_Encode_LUTI2_VG2_S
PUBLIC SME2_Encode_LUTI2_VG4_S
PUBLIC SME2_Encode_LUTI4_VG2_S
PUBLIC SME2_Encode_LUTI4_VG4_S
PUBLIC SME2_Encode_LUTI2_VG2_H
PUBLIC SME2_Encode_LUTI2_VG4_H
PUBLIC SME2_Encode_LUTI4_VG2_H
PUBLIC SME2_Encode_LUTI4_VG4_H
PUBLIC SME2_Encode_LUTI2_VG2_B
PUBLIC SME2_Encode_LUTI2_VG4_B
PUBLIC SME2_Encode_LUTI4_VG2_B
PUBLIC SME2_Encode_LUTI4_VG4_B
PUBLIC SME2_Encode_LUTI2_VG2_D
PUBLIC SME2_Encode_LUTI2_VG4_D
PUBLIC SME2_Encode_LUTI4_VG2_D
PUBLIC SME2_Encode_LUTI4_VG4_D

.code

; ============================================================================
; SME2_Encode_LDR_ZT0: LDR ZT0, [Xn, #offset]
;   Load 512-bit lookup table into ZT0 register
;   ECX = Base Register Xn (0..31)
;   EDX = Byte Offset (0..512, must be multiple of 64)
; ============================================================================
SME2_Encode_LDR_ZT0 PROC
    mov eax, 0E11F0000h           ; Base LDR ZT0 opcode template
    and ecx, 01Fh                 ; Base GP Xn (bits 5..9)
    shr edx, 6                    ; Scale offset by 64 bytes
    and edx, 007h                 ; 3-bit offset field (bits 10..12)

    shl ecx, 5
    shl edx, 10
    or eax, ecx
    or eax, edx
    ret
SME2_Encode_LDR_ZT0 ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG2_S: LUTI2 { Zd1.S, Zd2.S }, ZT0, Zn.B, #index
;   2-bit index -> FP32, VG2 destination tuple
;   ECX = Zd base (0, 2, 4, ... 30) - Must be even!
;   EDX = Zn Index Register (0..31)
;   R8D = Sub-index offset (0..7)
; ============================================================================
SME2_Encode_LUTI2_VG2_S PROC
    mov eax, 0C5000000h           ; Base LUTI2 VG2 Single-Precision
    and ecx, 01Eh                 ; Zd base (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 007h                 ; Index imm3 (bits 10..12)

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG2_S ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG4_S: LUTI2 { Zd1.S - Zd4.S }, ZT0, Zn.B, #index
;   2-bit index -> FP32, VG4 destination tuple
;   ECX = Zd base (0, 4, 8, ... 28) - Must be quad-aligned!
;   EDX = Zn Index Register (0..31)
;   R8D = Sub-index offset (0..7)
; ============================================================================
SME2_Encode_LUTI2_VG4_S PROC
    mov eax, 0C5000020h           ; Bit 5 = 1 for VG4 expansion
    and ecx, 01Ch                 ; Zd base quad-aligned (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 007h                 ; Index imm3 (bits 10..12)

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG4_S ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG2_S: LUTI4 { Zd1.S, Zd2.S }, ZT0, Zn.B, #index
;   4-bit index -> FP32, VG2 destination tuple
;   ECX = Zd base (0, 2, 4, ... 30) - Must be even!
;   EDX = Zn Index Register (0..31)
;   R8D = Sub-index offset (0..3)
; ============================================================================
SME2_Encode_LUTI4_VG2_S PROC
    mov eax, 0C5080000h           ; Base LUTI4 VG2 Single-Precision
    and ecx, 01Eh                 ; Zd base (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 003h                 ; Index imm2 (bits 10..11)

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG2_S ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG4_S: LUTI4 { Zd1.S - Zd4.S }, ZT0, Zn.B, #index
;   4-bit index -> FP32, VG4 destination tuple
;   ECX = Zd base (0, 4, 8, ... 28) - Must be quad-aligned!
;   EDX = Zn Index Register (0..31)
;   R8D = Sub-index offset (0..3)
; ============================================================================
SME2_Encode_LUTI4_VG4_S PROC
    mov eax, 0C5080020h           ; Bit 5 = 1 for VG4 expansion
    and ecx, 01Ch                 ; Zd base quad-aligned (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 003h                 ; Index imm2 (bits 10..11)

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG4_S ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG2_H: LUTI2 { Zd1.H, Zd2.H }, ZT0, Zn.B, #index
;   2-bit index -> FP16, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG2_H PROC
    mov eax, 0C5040000h           ; Base LUTI2 VG2 Half-Precision
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG2_H ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG4_H: LUTI2 { Zd1.H - Zd4.H }, ZT0, Zn.B, #index
;   2-bit index -> FP16, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG4_H PROC
    mov eax, 0C5040020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG4_H ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG2_H: LUTI4 { Zd1.H, Zd2.H }, ZT0, Zn.B, #index
;   4-bit index -> FP16, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG2_H PROC
    mov eax, 0C50C0000h           ; Base LUTI4 VG2 Half-Precision
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG2_H ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG4_H: LUTI4 { Zd1.H - Zd4.H }, ZT0, Zn.B, #index
;   4-bit index -> FP16, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG4_H PROC
    mov eax, 0C50C0020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG4_H ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG2_B: LUTI2 { Zd1.B, Zd2.B }, ZT0, Zn.B, #index
;   2-bit index -> INT8, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG2_B PROC
    mov eax, 0C5080000h           ; Base LUTI2 VG2 Byte
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG2_B ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG4_B: LUTI2 { Zd1.B - Zd4.B }, ZT0, Zn.B, #index
;   2-bit index -> INT8, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG4_B PROC
    mov eax, 0C5080020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG4_B ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG2_B: LUTI4 { Zd1.B, Zd2.B }, ZT0, Zn.B, #index
;   4-bit index -> INT8, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG2_B PROC
    mov eax, 0C5100000h           ; Base LUTI4 VG2 Byte
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG2_B ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG4_B: LUTI4 { Zd1.B - Zd4.B }, ZT0, Zn.B, #index
;   4-bit index -> INT8, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG4_B PROC
    mov eax, 0C5100020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG4_B ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG2_D: LUTI2 { Zd1.D, Zd2.D }, ZT0, Zn.B, #index
;   2-bit index -> FP64, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG2_D PROC
    mov eax, 0C50C0000h           ; Base LUTI2 VG2 Double-Precision
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG2_D ENDP

; ============================================================================
; SME2_Encode_LUTI2_VG4_D: LUTI2 { Zd1.D - Zd4.D }, ZT0, Zn.B, #index
;   2-bit index -> FP64, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI2_VG4_D PROC
    mov eax, 0C50C0020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 007h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI2_VG4_D ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG2_D: LUTI4 { Zd1.D, Zd2.D }, ZT0, Zn.B, #index
;   4-bit index -> FP64, VG2 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG2_D PROC
    mov eax, 0C5140000h           ; Base LUTI4 VG2 Double-Precision
    and ecx, 01Eh
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG2_D ENDP

; ============================================================================
; SME2_Encode_LUTI4_VG4_D: LUTI4 { Zd1.D - Zd4.D }, ZT0, Zn.B, #index
;   4-bit index -> FP64, VG4 destination tuple
; ============================================================================
SME2_Encode_LUTI4_VG4_D PROC
    mov eax, 0C5140020h
    and ecx, 01Ch
    and edx, 01Fh
    and r8d, 003h

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SME2_Encode_LUTI4_VG4_D ENDP

END
