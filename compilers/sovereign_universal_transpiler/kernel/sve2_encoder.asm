; ============================================================================
; kernel/sve2_encoder.asm - ARM64 SVE2 & Segment Bitfield Encoder
; Complex arithmetic, bitwise permutations, and multi-vector operations
; ============================================================================

option casemap:none

PUBLIC SVE2_Encode_BPERM
PUBLIC SVE2_Encode_EOR3
PUBLIC SVE2_Encode_FCADD
PUBLIC SVE2_Encode_FCMLA
PUBLIC SVE2_Encode_LD2W_Reg
PUBLIC SVE2_Encode_ST2W_Reg
PUBLIC SVE2_Encode_LD4W_Reg
PUBLIC SVE2_Encode_ST4W_Reg
PUBLIC SVE2_Encode_LD2D_Reg
PUBLIC SVE2_Encode_ST2D_Reg
PUBLIC SVE2_Encode_TBL
PUBLIC SVE2_Encode_TBX
PUBLIC SVE2_Encode_CADD
PUBLIC SVE2_Encode_CMLA
PUBLIC SVE2_Encode_SADDV
PUBLIC SVE2_Encode_UADDV

.code

; ============================================================================
; SVE2_Encode_BPERM: BPERM Zd.S, Zn.S, Zm.S (Bitwise Permute Bytes)
;   ECX = Zd, EDX = Zn, R8D = Zm
; ============================================================================
SVE2_Encode_BPERM PROC
    ; Base Template: 0x04603000 (size=10 [32-bit])
    mov eax, 004603000h
    and ecx, 01Fh                 ; Zd (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 01Fh                 ; Zm (bits 16..20)

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE2_Encode_BPERM ENDP

; ============================================================================
; SVE2_Encode_EOR3: EOR3 Zd.S, Zn.S, Zm.S, Zk.S (Three-Way XOR)
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Zk
; ============================================================================
SVE2_Encode_EOR3 PROC
    ; Base Template: 0x04200000
    mov eax, 004200000h
    and ecx, 01Fh                 ; Zd (bits 0..4)
    and edx, 01Fh                 ; Zn (bits 5..9)
    and r8d, 01Fh                 ; Zm (bits 16..20)
    and r9d, 01Fh                 ; Zk (bits 10..14)

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE2_Encode_EOR3 ENDP

; ============================================================================
; SVE2_Encode_FCADD: FCADD Zd.S, Pg/M, Zn.S, Zm.S, #rot
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
;   Stack [RSP+28h] = Rot Angle (0=#90, 1=#270)
; ============================================================================
SVE2_Encode_FCADD PROC
    mov eax, 064209000h           ; Base FCADD size=10 (32-bit float)
    and ecx, 01Fh                 ; Zd
    and edx, 01Fh                 ; Zn
    and r8d, 01Fh                 ; Zm
    and r9d, 007h                 ; Pg

    mov r10d, dword ptr [rsp + 28h] ; Load rot parameter
    and r10d, 01h                 ; Bit 13 controls rotation
    shl r10d, 13

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    or eax, r10d
    ret
SVE2_Encode_FCADD ENDP

; ============================================================================
; SVE2_Encode_FCMLA: FCMLA Zd.S, Pg/M, Zn.S, Zm.S, #rot
;   ECX = Zd, EDX = Zn, R8D = Zm, R9D = Pg
;   Stack [RSP+28h] = Rot Angle (0=#0, 1=#90, 2=#180, 3=#270)
; ============================================================================
SVE2_Encode_FCMLA PROC
    mov eax, 06420C000h           ; Base FCMLA size=10
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh
    and r9d, 007h

    mov r10d, dword ptr [rsp + 28h]
    and r10d, 03h                 ; Bits 13..14 control rotation
    shl r10d, 13

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    or eax, r10d
    ret
SVE2_Encode_FCMLA ENDP

; ============================================================================
; SVE2_Encode_LD2W_Reg: LD2W { Zt1.S, Zt2.S }, Pg/Z, [Xn, Xm, LSL #2]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_LD2W_Reg PROC
    ; Base Template: 0xA5604000 (size=10 [32-bit], dtype=01 [2 structures])
    mov eax, 0A5604000h
    and ecx, 01Fh                 ; Zt1
    and edx, 01Fh                 ; Xn
    and r8d, 01Fh                 ; Xm
    and r9d, 007h                 ; Pg

    shl edx, 5
    shl r9d, 10
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE2_Encode_LD2W_Reg ENDP

; ============================================================================
; SVE2_Encode_ST2W_Reg: ST2W { Zt1.S, Zt2.S }, Pg, [Xn, Xm, LSL #2]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_ST2W_Reg PROC
    ; Base Template: 0xE5604000
    mov eax, 0E5604000h
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
SVE2_Encode_ST2W_Reg ENDP

; ============================================================================
; SVE2_Encode_LD4W_Reg: LD4W { Zt1.S..Zt4.S }, Pg/Z, [Xn, Xm, LSL #2]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_LD4W_Reg PROC
    ; Base Template: 0xA5A04000 (size=10, dtype=11 [4 structures])
    mov eax, 0A5A04000h
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
SVE2_Encode_LD4W_Reg ENDP

; ============================================================================
; SVE2_Encode_ST4W_Reg: ST4W { Zt1.S..Zt4.S }, Pg, [Xn, Xm, LSL #2]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_ST4W_Reg PROC
    ; Base Template: 0xE5A04000
    mov eax, 0E5A04000h
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
SVE2_Encode_ST4W_Reg ENDP

; ============================================================================
; SVE2_Encode_LD2D_Reg: LD2D { Zt1.D, Zt2.D }, Pg/Z, [Xn, Xm, LSL #3]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_LD2D_Reg PROC
    ; Base Template: 0xA5E04000 (size=11 [64-bit])
    mov eax, 0A5E04000h
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
SVE2_Encode_LD2D_Reg ENDP

; ============================================================================
; SVE2_Encode_ST2D_Reg: ST2D { Zt1.D, Zt2.D }, Pg, [Xn, Xm, LSL #3]
;   ECX = Zt1, EDX = Xn, R8D = Xm, R9D = Pg
; ============================================================================
SVE2_Encode_ST2D_Reg PROC
    ; Base Template: 0xE5E04000
    mov eax, 0E5E04000h
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
SVE2_Encode_ST2D_Reg ENDP

; ============================================================================
; SVE2_Encode_TBL: TBL Zd.S, { Zn.S }, Zm.S (Table lookup)
;   ECX = Zd, EDX = Zn, R8D = Zm
; ============================================================================
SVE2_Encode_TBL PROC
    ; Base Template: 0x05203000
    mov eax, 005203000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE2_Encode_TBL ENDP

; ============================================================================
; SVE2_Encode_TBX: TBX Zd.S, { Zn.S }, Zm.S (Table lookup and extend)
;   ECX = Zd, EDX = Zn, R8D = Zm
; ============================================================================
SVE2_Encode_TBX PROC
    ; Base Template: 0x05203400
    mov eax, 005203400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE2_Encode_TBX ENDP

; ============================================================================
; SVE2_Encode_CADD: CADD Zd.S, Zn.S, Zm.S, #rot (Complex Add)
;   ECX = Zd, EDX = Zn, R8D = Zm
;   Stack [RSP+28h] = Rot (0=#90, 1=#270)
; ============================================================================
SVE2_Encode_CADD PROC
    ; Base Template: 0x04E00000
    mov eax, 004E00000h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    mov r9d, dword ptr [rsp + 28h]
    and r9d, 01h
    shl r9d, 10

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE2_Encode_CADD ENDP

; ============================================================================
; SVE2_Encode_CMLA: CMLA Zd.S, Zn.S, Zm.S, #rot (Complex MLA)
;   ECX = Zd, EDX = Zn, R8D = Zm
;   Stack [RSP+28h] = Rot (0-3)
; ============================================================================
SVE2_Encode_CMLA PROC
    ; Base Template: 0x04E00400
    mov eax, 004E00400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    mov r9d, dword ptr [rsp + 28h]
    and r9d, 03h
    shl r9d, 10

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r9d
    or eax, r8d
    ret
SVE2_Encode_CMLA ENDP

; ============================================================================
; SVE2_Encode_SADDV: SADDV Dd, Pg, Zn.S (Signed add reduction)
;   ECX = Dd (0..31), EDX = Pg, R8D = Zn
; ============================================================================
SVE2_Encode_SADDV PROC
    ; Base Template: 0x04012000
    mov eax, 004012000h
    and ecx, 01Fh
    and edx, 007h
    and r8d, 01Fh

    shl edx, 10
    shl r8d, 5
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE2_Encode_SADDV ENDP

; ============================================================================
; SVE2_Encode_UADDV: UADDV Dd, Pg, Zn.S (Unsigned add reduction)
;   ECX = Dd, EDX = Pg, R8D = Zn
; ============================================================================
SVE2_Encode_UADDV PROC
    ; Base Template: 0x04012400
    mov eax, 004012400h
    and ecx, 01Fh
    and edx, 007h
    and r8d, 01Fh

    shl edx, 10
    shl r8d, 5
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
SVE2_Encode_UADDV ENDP

END
