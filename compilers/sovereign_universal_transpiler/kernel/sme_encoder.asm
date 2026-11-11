; ============================================================================
; kernel/sme_encoder.asm - ARM64 SME (Scalable Matrix Extension) Encoder
; Matrix operations, ZA accumulator management, streaming mode
; ============================================================================

option casemap:none

PUBLIC SME_Encode_SMSTART
PUBLIC SME_Encode_SMSTOP
PUBLIC SME_Encode_ZERO
PUBLIC SME_Encode_ZERO_ZA
PUBLIC SME_Encode_FMOPA_S
PUBLIC SME_Encode_FMOPS_S
PUBLIC SME_Encode_FMOPA_D
PUBLIC SME_Encode_FMOPS_D
PUBLIC SME_Encode_LD1W_Tile
PUBLIC SME_Encode_ST1W_Tile
PUBLIC SME_Encode_LD1D_Tile
PUBLIC SME_Encode_ST1D_Tile
PUBLIC SME_Encode_MOVA_V
PUBLIC SME_Encode_MOVA_T
PUBLIC SME_Encode_ADDHA
PUBLIC SME_Encode_ADDVA

.code

; ============================================================================
; SME_Encode_SMSTART: Enable Streaming Mode and/or ZA Storage
;   ECX = Flags (1 = SM only, 2 = ZA only, 3 = SM & ZA)
; ============================================================================
SME_Encode_SMSTART PROC
    cmp ecx, 1
    je sm_only
    cmp ecx, 2
    je za_only

    ; Default: SMSTART (SM & ZA) -> MSR SVCRSMZA, #1
    mov eax, 0D503437Fh
    ret

sm_only:
    mov eax, 0D503417Fh
    ret

za_only:
    mov eax, 0D503427Fh
    ret
SME_Encode_SMSTART ENDP

; ============================================================================
; SME_Encode_SMSTOP: Disable Streaming Mode and/or ZA Storage
;   ECX = Flags (1 = SM only, 2 = ZA only, 3 = SM & ZA)
; ============================================================================
SME_Encode_SMSTOP PROC
    cmp ecx, 1
    je sm_only
    cmp ecx, 2
    je za_only

    ; Default: SMSTOP (SM & ZA) -> MSR SVCRSMZA, #0
    mov eax, 0D503401Fh
    ret

sm_only:
    mov eax, 0D503411Fh
    ret

za_only:
    mov eax, 0D503421Fh
    ret
SME_Encode_SMSTOP ENDP

; ============================================================================
; SME_Encode_ZERO: ZERO { ZA_mask }
;   ECX = 8-bit Tile Bitmask (Bit 0 = ZA0.S, Bit 1 = ZA1.S, etc.)
; ============================================================================
SME_Encode_ZERO PROC
    mov eax, 0C0080000h           ; Base ZERO instruction
    and ecx, 0FFh                 ; Mask to 8 tile bits
    or eax, ecx
    ret
SME_Encode_ZERO ENDP

; ============================================================================
; SME_Encode_ZERO_ZA: ZERO { ZA } (Zero entire ZA array)
; ============================================================================
SME_Encode_ZERO_ZA PROC
    mov eax, 0C00800FFh           ; All tiles
    ret
SME_Encode_ZERO_ZA ENDP

; ============================================================================
; SME_Encode_FMOPA_S: FMOPA ZAda.S, Pn/M, Pm/M, Zn.S, Zm.S
;   ECX = ZAda (0..3 for 32-bit tiles ZA0.S..ZA3.S)
;   EDX = Zn, R8D = Zm, R9D = Pn
;   Stack [RSP+28h] = Pm
; ============================================================================
SME_Encode_FMOPA_S PROC
    mov eax, 080200000h           ; Base FMOPA single-precision
    and ecx, 003h                 ; ZAda tile index (bits 0..1)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 01Fh                 ; Zm (bits 16..20)
    and r9d, 007h                 ; Pn (bits 10..12)

    mov r10d, dword ptr [rsp + 28h] ; Load Pm
    and r10d, 007h
    shl r10d, 13                  ; Pm field (bits 13..15)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r10d
    or eax, r8d
    ret
SME_Encode_FMOPA_S ENDP

; ============================================================================
; SME_Encode_FMOPS_S: FMOPS ZAda.S, Pn/M, Pm/M, Zn.S, Zm.S (Subtract)
; ============================================================================
SME_Encode_FMOPS_S PROC
    mov eax, 080200010h           ; Bit 4 = 1 for FMOPS
    and ecx, 003h
    and edx, 01Fh
    and r8d, 01Fh
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
SME_Encode_FMOPS_S ENDP

; ============================================================================
; SME_Encode_FMOPA_D: FMOPA ZAda.D, Pn/M, Pm/M, Zn.D, Zm.D (64-bit)
; ============================================================================
SME_Encode_FMOPA_D PROC
    mov eax, 082200000h           ; Base with size=11 for double
    and ecx, 001h                 ; ZAda tile index (0..1 for 64-bit)
    and edx, 01Fh
    and r8d, 01Fh
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
SME_Encode_FMOPA_D ENDP

; ============================================================================
; SME_Encode_FMOPS_D: FMOPS ZAda.D, Pn/M, Pm/M, Zn.D, Zm.D
; ============================================================================
SME_Encode_FMOPS_D PROC
    mov eax, 082200010h           ; Subtract variant
    and ecx, 001h
    and edx, 01Fh
    and r8d, 01Fh
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
SME_Encode_FMOPS_D ENDP

; ============================================================================
; SME_Encode_LD1W_Tile: LD1W { ZAda.S[Wv, off] }, Pg/Z, [Xn, Xm]
;   ECX = ZAda, EDX = Xn, R8D = Xm, R9D = Pg
;   Stack [RSP+28h] = Slice Offset (0..3)
;   Stack [RSP+30h] = Vertical Flag (0 = Horizontal, 1 = Vertical)
; ============================================================================
SME_Encode_LD1W_Tile PROC
    mov eax, 0E1000000h           ; Base LD1W tile slice
    and ecx, 003h                 ; ZAda (bits 0..1)
    and edx, 01Fh                 ; Xn (bits 5..9)
    and r8d, 01Fh                 ; Xm (bits 16..20)
    and r9d, 007h                 ; Pg (bits 10..12)

    mov r10d, dword ptr [rsp + 28h] ; Slice offset
    and r10d, 003h
    shl r10d, 2                   ; Offset field (bits 2..3)

    mov r11d, dword ptr [rsp + 30h] ; Vertical/Horizontal
    and r11d, 001h
    shl r11d, 15                  ; Bit 15: V=1 (Vertical)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, r10d
    or eax, edx
    or eax, r9d
    or eax, r11d
    or eax, r8d
    ret
SME_Encode_LD1W_Tile ENDP

; ============================================================================
; SME_Encode_ST1W_Tile: ST1W { ZAda.S[Wv, off] }, Pg, [Xn, Xm]
; ============================================================================
SME_Encode_ST1W_Tile PROC
    mov eax, 0E1200000h           ; Base ST1W
    and ecx, 003h
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 003h
    shl r10d, 2

    mov r11d, dword ptr [rsp + 30h]
    and r11d, 001h
    shl r11d, 15

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, r10d
    or eax, edx
    or eax, r9d
    or eax, r11d
    or eax, r8d
    ret
SME_Encode_ST1W_Tile ENDP

; ============================================================================
; SME_Encode_LD1D_Tile: LD1D { ZAda.D[Wv, off] }, Pg/Z, [Xn, Xm]
; ============================================================================
SME_Encode_LD1D_Tile PROC
    mov eax, 0E5000000h           ; Base LD1D (64-bit)
    and ecx, 001h                 ; ZAda (0..1 for 64-bit)
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 003h
    shl r10d, 2

    mov r11d, dword ptr [rsp + 30h]
    and r11d, 001h
    shl r11d, 15

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, r10d
    or eax, edx
    or eax, r9d
    or eax, r11d
    or eax, r8d
    ret
SME_Encode_LD1D_Tile ENDP

; ============================================================================
; SME_Encode_ST1D_Tile: ST1D { ZAda.D[Wv, off] }, Pg, [Xn, Xm]
; ============================================================================
SME_Encode_ST1D_Tile PROC
    mov eax, 0E5200000h           ; Base ST1D
    and ecx, 001h
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 003h
    shl r10d, 2

    mov r11d, dword ptr [rsp + 30h]
    and r11d, 001h
    shl r11d, 15

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, r10d
    or eax, edx
    or eax, r9d
    or eax, r11d
    or eax, r8d
    ret
SME_Encode_ST1D_Tile ENDP

; ============================================================================
; SME_Encode_MOVA_V: MOVA Zd.S, Pg/M, ZAda.S[Wv, off] (Tile to Vector)
; ============================================================================
SME_Encode_MOVA_V PROC
    mov eax, 0C0900000h           ; Base MOVA vector
    and ecx, 01Fh                 ; Zd
    and edx, 007h                 ; Pg
    and r8d, 003h                 ; ZAda
    and r9d, 003h                 ; Slice offset

    shl edx, 10
    shl r8d, 16
    shl r9d, 2
    or eax, ecx
    or eax, edx
    or eax, r8d
    or eax, r9d
    ret
SME_Encode_MOVA_V ENDP

; ============================================================================
; SME_Encode_MOVA_T: MOVA ZAda.S[Wv, off], Pg/M, Zn.S (Vector to Tile)
; ============================================================================
SME_Encode_MOVA_T PROC
    mov eax, 0C0980000h           ; Base MOVA tile
    and ecx, 003h                 ; ZAda
    and edx, 007h                 ; Pg
    and r8d, 01Fh                 ; Zn
    and r9d, 003h                 ; Slice offset

    shl edx, 10
    shl r8d, 5
    shl r9d, 2
    or eax, ecx
    or eax, edx
    or eax, r8d
    or eax, r9d
    ret
SME_Encode_MOVA_T ENDP

; ============================================================================
; SME_Encode_ADDHA: ADDHA ZAda.S, Pg/M, Zn.S, Zm.S (Horizontal add to tile)
; ============================================================================
SME_Encode_ADDHA PROC
    mov eax, 0C0200000h           ; Base ADDHA
    and ecx, 003h                 ; ZAda
    and edx, 007h                 ; Pg
    and r8d, 01Fh                 ; Zn
    and r9d, 01Fh                 ; Zm

    shl edx, 10
    shl r8d, 5
    shl r9d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    or eax, r9d
    ret
SME_Encode_ADDHA ENDP

; ============================================================================
; SME_Encode_ADDVA: ADDVA ZAda.S, Pg/M, Zn.S, Zm.S (Vertical add to tile)
; ============================================================================
SME_Encode_ADDVA PROC
    mov eax, 0C0280000h           ; Base ADDVA
    and ecx, 003h
    and edx, 007h
    and r8d, 01Fh
    and r9d, 01Fh

    shl edx, 10
    shl r8d, 5
    shl r9d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    or eax, r9d
    ret
SME_Encode_ADDVA ENDP

END
