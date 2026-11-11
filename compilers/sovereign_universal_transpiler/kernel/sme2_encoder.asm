; ============================================================================
; kernel/sme2_encoder.asm - ARM64 SME2 Multi-Vector Outer-Product Encoders
; VG2 (2-way) and VG4 (4-way) tuple operations for matrix acceleration
; ============================================================================

option casemap:none

PUBLIC SME2_Encode_FMOPA_VG2_S
PUBLIC SME2_Encode_FMOPA_VG4_S
PUBLIC SME2_Encode_FMOPA_VG2_D
PUBLIC SME2_Encode_FMOPA_VG4_D
PUBLIC SME2_Encode_LD1W_VG2
PUBLIC SME2_Encode_LD1W_VG4
PUBLIC SME2_Encode_ST1W_VG2
PUBLIC SME2_Encode_ST1W_VG4
PUBLIC SME2_Encode_LD1D_VG2
PUBLIC SME2_Encode_LD1D_VG4
PUBLIC SME2_Encode_ST1D_VG2
PUBLIC SME2_Encode_ST1D_VG4
PUBLIC SME2_Encode_ZERO_VG2
PUBLIC SME2_Encode_ZERO_VG4
PUBLIC SME2_Encode_SMSTART_VG4
PUBLIC SME2_Encode_SMSTOP_VG4

.code

; ============================================================================
; SME2_Encode_FMOPA_VG2_S: FMOPA ZAda.S, Pn/M, Pm/M, Zn1.S-Zn2.S, Zm1.S-Zm2.S
;   ECX = ZAda tile (0..3)
;   EDX = Zn base (0, 2, 4, ... 30) - Must be even!
;   R8D = Zm base (0, 2, 4, ... 30) - Must be even!
;   R9D = Pn (0..7)
;   Stack Param [RSP+28h] = Pm (0..7)
; ============================================================================
SME2_Encode_FMOPA_VG2_S PROC
    mov eax, 080A00000h           ; Base SME2 VG2 Single-Precision FMOPA
    and ecx, 003h                 ; ZAda (bits 0..1)
    
    ; Shift base registers (bit 0 implicit 0 for VG2)
    and edx, 01Eh                 ; Zn base (bits 5..9)
    and r8d, 01Eh                 ; Zm base (bits 16..20)
    and r9d, 007h                 ; Pn (bits 10..12)

    mov r10d, dword ptr [rsp + 28h] ; Load Pm from stack
    and r10d, 007h
    shl r10d, 13                  ; Pm (bits 13..15)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r10d
    or eax, r8d
    ret
SME2_Encode_FMOPA_VG2_S ENDP

; ============================================================================
; SME2_Encode_FMOPA_VG4_S: FMOPA ZAda.S, Pn/M, Pm/M, Zn1.S-Zn4.S, Zm1.S-Zm4.S
;   ECX = ZAda tile (0..3)
;   EDX = Zn base (0, 4, 8, ... 28) - Must be quad-aligned!
;   R8D = Zm base (0, 4, 8, ... 28) - Must be quad-aligned!
;   R9D = Pn (0..7)
;   Stack Param [RSP+28h] = Pm (0..7)
; ============================================================================
SME2_Encode_FMOPA_VG4_S PROC
    mov eax, 080B00000h           ; Base SME2 VG4 Single-Precision FMOPA
    and ecx, 003h                 ; ZAda (bits 0..1)
    
    and edx, 01Ch                 ; Zn base (bits 5..9, lower 2 bits zero)
    and r8d, 01Ch                 ; Zm base (bits 16..20, lower 2 bits zero)
    and r9d, 007h                 ; Pn (bits 10..12)

    mov r10d, dword ptr [rsp + 28h] ; Load Pm from stack
    and r10d, 007h
    shl r10d, 13                  ; Pm (bits 13..15)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r10d
    or eax, r8d
    ret
SME2_Encode_FMOPA_VG4_S ENDP

; ============================================================================
; SME2_Encode_FMOPA_VG2_D: FMOPA ZAda.D, Pn/M, Pm/M, Zn1.D-Zn2.D, Zm1.D-Zm2.D
;   Double-precision VG2 outer product
; ============================================================================
SME2_Encode_FMOPA_VG2_D PROC
    mov eax, 08C0A0000h           ; Base SME2 VG2 Double-Precision FMOPA
    and ecx, 003h
    and edx, 01Eh
    and r8d, 01Eh
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 007h
    shl r10d, 13

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r10d
    or eax, r8d
    ret
SME2_Encode_FMOPA_VG2_D ENDP

; ============================================================================
; SME2_Encode_FMOPA_VG4_D: FMOPA ZAda.D, Pn/M, Pm/M, Zn1.D-Zn4.D, Zm1.D-Zm4.D
;   Double-precision VG4 outer product
; ============================================================================
SME2_Encode_FMOPA_VG4_D PROC
    mov eax, 08C0B0000h           ; Base SME2 VG4 Double-Precision FMOPA
    and ecx, 003h
    and edx, 01Ch
    and r8d, 01Ch
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 007h
    shl r10d, 13

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r10d
    or eax, r8d
    ret
SME2_Encode_FMOPA_VG4_D ENDP

; ============================================================================
; SME2_Encode_LD1W_VG2: LD1W { Zt1.S, Zt2.S }, Pg/Z, [Xn, Xm]
;   ECX = Zt base (0, 2, ... 30)
;   EDX = Xn Base GP (0..31)
;   R8D = Xm Index GP (0..31)
;   R9D = Pg Predicate (0..7)
; ============================================================================
SME2_Encode_LD1W_VG2 PROC
    mov eax, 0A1000000h           ; Base SME2 LD1W VG2 opcode
    and ecx, 01Eh                 ; Zt base (bits 0..4)
    and edx, 01Fh                 ; Xn (bits 5..9)
    and r8d, 01Fh                 ; Xm (bits 16..20)
    and r9d, 007h                 ; Pg (bits 10..12)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LD1W_VG2 ENDP

; ============================================================================
; SME2_Encode_LD1W_VG4: LD1W { Zt1.S - Zt4.S }, Pg/Z, [Xn, Xm]
;   ECX = Zt base (0, 4, ... 28)
;   EDX = Xn Base GP (0..31)
;   R8D = Xm Index GP (0..31)
;   R9D = Pg Predicate (0..7)
; ============================================================================
SME2_Encode_LD1W_VG4 PROC
    mov eax, 0A1200000h           ; Base SME2 LD1W VG4 opcode
    and ecx, 01Ch                 ; Zt base (bits 0..4)
    and edx, 01Fh                 ; Xn (bits 5..9)
    and r8d, 01Fh                 ; Xm (bits 16..20)
    and r9d, 007h                 ; Pg (bits 10..12)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16

    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SME2_Encode_LD1W_VG4 ENDP

; ============================================================================
; SME2_Encode_ST1W_VG2: ST1W { Zt1.S, Zt2.S }, Pg, [Xn, Xm]
; ============================================================================
SME2_Encode_ST1W_VG2 PROC
    mov eax, 0A1200000h           ; Base SME2 ST1W VG2 opcode
    and ecx, 01Eh
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
SME2_Encode_ST1W_VG2 ENDP

; ============================================================================
; SME2_Encode_ST1W_VG4: ST1W { Zt1.S - Zt4.S }, Pg, [Xn, Xm]
; ============================================================================
SME2_Encode_ST1W_VG4 PROC
    mov eax, 0A3200000h           ; Base SME2 ST1W VG4 opcode
    and ecx, 01Ch
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
SME2_Encode_ST1W_VG4 ENDP

; ============================================================================
; SME2_Encode_LD1D_VG2: LD1D { Zt1.D, Zt2.D }, Pg/Z, [Xn, Xm]
;   Double-precision VG2 load
; ============================================================================
SME2_Encode_LD1D_VG2 PROC
    mov eax, 0A1400000h           ; Base SME2 LD1D VG2 opcode
    and ecx, 01Eh
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
SME2_Encode_LD1D_VG2 ENDP

; ============================================================================
; SME2_Encode_LD1D_VG4: LD1D { Zt1.D - Zt4.D }, Pg/Z, [Xn, Xm]
;   Double-precision VG4 load
; ============================================================================
SME2_Encode_LD1D_VG4 PROC
    mov eax, 0A1600000h           ; Base SME2 LD1D VG4 opcode
    and ecx, 01Ch
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
SME2_Encode_LD1D_VG4 ENDP

; ============================================================================
; SME2_Encode_ST1D_VG2: ST1D { Zt1.D, Zt2.D }, Pg, [Xn, Xm]
; ============================================================================
SME2_Encode_ST1D_VG2 PROC
    mov eax, 0A3400000h
    and ecx, 01Eh
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
SME2_Encode_ST1D_VG2 ENDP

; ============================================================================
; SME2_Encode_ST1D_VG4: ST1D { Zt1.D - Zt4.D }, Pg, [Xn, Xm]
; ============================================================================
SME2_Encode_ST1D_VG4 PROC
    mov eax, 0A3600000h
    and ecx, 01Ch
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
SME2_Encode_ST1D_VG4 ENDP

; ============================================================================
; SME2_Encode_ZERO_VG2: ZERO { ZA_mask } for VG2 tile group
;   ECX = 8-bit Tile Bitmask
; ============================================================================
SME2_Encode_ZERO_VG2 PROC
    mov eax, 0C0080000h           ; Base ZERO instruction
    and ecx, 0FFh
    or eax, ecx
    ret
SME2_Encode_ZERO_VG2 ENDP

; ============================================================================
; SME2_Encode_ZERO_VG4: ZERO { ZA_mask } for VG4 tile group
; ============================================================================
SME2_Encode_ZERO_VG4 PROC
    mov eax, 0C0090000h           ; Base ZERO VG4 variant
    and ecx, 0FFh
    or eax, ecx
    ret
SME2_Encode_ZERO_VG4 ENDP

; ============================================================================
; SME2_Encode_SMSTART_VG4: SMSTART with VG4 streaming mode
; ============================================================================
SME2_Encode_SMSTART_VG4 PROC
    mov eax, 0D503447Fh           ; MSR SVCRSMZA_VG4, #1
    ret
SME2_Encode_SMSTART_VG4 ENDP

; ============================================================================
; SME2_Encode_SMSTOP_VG4: SMSTOP with VG4 streaming mode
; ============================================================================
SME2_Encode_SMSTOP_VG4 PROC
    mov eax, 0D503441Fh           ; MSR SVCRSMZA_VG4, #0
    ret
SME2_Encode_SMSTOP_VG4 ENDP

END
