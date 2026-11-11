; ============================================================================
; kernel/a64_neon_encoder.asm - ARM64 Advanced SIMD (NEON) Bitfield Encoder
; ============================================================================

option casemap:none

PUBLIC A64_Encode_VLDR_128
PUBLIC A64_Encode_VSTR_128
PUBLIC A64_Encode_VADD_4S
PUBLIC A64_Encode_VFADD_4S
PUBLIC A64_Encode_VFMUL_4S
PUBLIC A64_Encode_VDUP_4S
PUBLIC A64_Encode_VLD1_4S
PUBLIC A64_Encode_VST1_4S
PUBLIC A64_Encode_VFMA_4S
PUBLIC A64_Encode_VCMEQ_4S
PUBLIC A64_Encode_VMAX_4S
PUBLIC A64_Encode_VMIN_4S
PUBLIC A64_Encode_VSHL_4S
PUBLIC A64_Encode_VSHR_4S

.code

; ============================================================================
; A64_Encode_VLDR_128: VLDR Qt, [Xn, #offset] (128-bit Vector Load)
;   ECX = Vt (Vector Target Register 0..31)
;   EDX = Xn (Base GP Pointer Register 0..31)
;   R8D = Byte Offset (Must be multiple of 16)
; ============================================================================
A64_Encode_VLDR_128 PROC
    ; Base Template: 0x3DC00000 (size=11, V=1, opc=01)
    mov eax, 03DC00000h
    and ecx, 01Fh                 ; Vt field (bits 0..4)
    and edx, 01Fh                 ; Xn base field (bits 5..9)
    shr r8d, 4                    ; Scale byte offset by 16
    and r8d, 0FFFh                ; imm12 field (bits 10..21)

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VLDR_128 ENDP

; ============================================================================
; A64_Encode_VSTR_128: VSTR Qt, [Xn, #offset] (128-bit Vector Store)
;   ECX = Vt (Vector Source Register 0..31)
;   EDX = Xn (Base GP Pointer Register 0..31)
;   R8D = Byte Offset (Must be multiple of 16)
; ============================================================================
A64_Encode_VSTR_128 PROC
    ; Base Template: 0x3D800000 (size=11, V=1, opc=00)
    mov eax, 03D800000h
    and ecx, 01Fh
    and edx, 01Fh
    shr r8d, 4
    and r8d, 0FFFh

    shl edx, 5
    shl r8d, 10
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VSTR_128 ENDP

; ============================================================================
; A64_Encode_VADD_4S: ADD Vd.4S, Vn.4S, Vm.4S (Vector 32-bit Integer Add)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VADD_4S PROC
    ; Base Template: 0x4E808000 (Q=1, U=0, size=10, 10000)
    mov eax, 04E808000h
    and ecx, 01Fh                 ; Vd (bits 0..4)
    and edx, 01Fh                 ; Vn (bits 5..9)
    and r8d, 01Fh                 ; Vm (bits 16..20)

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VADD_4S ENDP

; ============================================================================
; A64_Encode_VFADD_4S: FADD Vd.4S, Vn.4S, Vm.4S (Vector 32-bit Float Add)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VFADD_4S PROC
    ; Base Template: 0x4E20D400 (Q=1, U=0, size=00, 01101)
    mov eax, 04E20D400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VFADD_4S ENDP

; ============================================================================
; A64_Encode_VFMUL_4S: FMUL Vd.4S, Vn.4S, Vm.4S (Vector 32-bit Float Mul)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VFMUL_4S PROC
    ; Base Template: 0x4E20DC00 (Q=1, U=0, size=10, 01101)
    mov eax, 04E20DC00h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VFMUL_4S ENDP

; ============================================================================
; A64_Encode_VDUP_4S: DUP Vd.4S, Rn (Broadcast General Register to Vector)
;   ECX = Vd (Target Vector Register)
;   EDX = Rn (Source 32-bit GP Register)
; ============================================================================
A64_Encode_VDUP_4S PROC
    ; Base Template: 0x4E040C00 (Q=1, imm5=00100 for 32-bit element index)
    mov eax, 04E040C00h
    and ecx, 01Fh
    and edx, 01Fh

    shl edx, 5
    or eax, ecx
    or eax, edx
    ret
A64_Encode_VDUP_4S ENDP

; ============================================================================
; A64_Encode_VLD1_4S: LD1 {Vd.4S}, [Xn] (Load 4x32-bit elements)
;   ECX = Vd, EDX = Xn
; ============================================================================
A64_Encode_VLD1_4S PROC
    ; Base Template: 0x4C407000 (LD1 multiple 4-element structure)
    mov eax, 04C407000h
    and ecx, 01Fh                 ; Vd
    and edx, 01Fh                 ; Xn
    
    shl edx, 5
    or eax, ecx
    or eax, edx
    ret
A64_Encode_VLD1_4S ENDP

; ============================================================================
; A64_Encode_VST1_4S: ST1 {Vd.4S}, [Xn] (Store 4x32-bit elements)
;   ECX = Vd, EDX = Xn
; ============================================================================
A64_Encode_VST1_4S PROC
    ; Base Template: 0x4C007000 (ST1 multiple 4-element structure)
    mov eax, 04C007000h
    and ecx, 01Fh
    and edx, 01Fh
    
    shl edx, 5
    or eax, ecx
    or eax, edx
    ret
A64_Encode_VST1_4S ENDP

; ============================================================================
; A64_Encode_VFMA_4S: FMLA Vd.4S, Vn.4S, Vm.4S (Fused Multiply-Add)
;   ECX = Vd (Accumulator), EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VFMA_4S PROC
    ; Base Template: 0x4E20CC00 (Q=1, size=00, 01100)
    mov eax, 04E20CC00h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VFMA_4S ENDP

; ============================================================================
; A64_Encode_VCMEQ_4S: CMEQ Vd.4S, Vn.4S, Vm.4S (Compare Equal)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VCMEQ_4S PROC
    ; Base Template: 0x6E208400 (Q=1, U=1, size=10, 10001)
    mov eax, 06E208400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VCMEQ_4S ENDP

; ============================================================================
; A64_Encode_VMAX_4S: SMAX Vd.4S, Vn.4S, Vm.4S (Signed Maximum)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VMAX_4S PROC
    ; Base Template: 0x4E606400 (Q=1, U=0, size=10, 01100)
    mov eax, 04E606400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VMAX_4S ENDP

; ============================================================================
; A64_Encode_VMIN_4S: SMIN Vd.4S, Vn.4S, Vm.4S (Signed Minimum)
;   ECX = Vd, EDX = Vn, R8D = Vm
; ============================================================================
A64_Encode_VMIN_4S PROC
    ; Base Template: 0x4E606C00 (Q=1, U=0, size=10, 01101)
    mov eax, 04E606C00h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 01Fh

    shl edx, 5
    shl r8d, 16
    or eax, ecx
    or eax, edx
    or eax, r8d
    ret
A64_Encode_VMIN_4S ENDP

; ============================================================================
; A64_Encode_VSHL_4S: SHL Vd.4S, Vn.4S, #imm (Vector Shift Left)
;   ECX = Vd, EDX = Vn, R8D = Shift amount (1-32)
; ============================================================================
A64_Encode_VSHL_4S PROC
    ; Base Template: 0x4F005400 (SHL immediate, Q=1, immh=0001)
    mov eax, 04F005400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 03Fh                 ; Shift amount 0-63
    
    ; Encode shift amount into immh:immb
    mov r9d, r8d
    shl r9d, 16                   ; immh:immb field
    
    shl edx, 5
    or eax, ecx
    or eax, edx
    or eax, r9d
    ret
A64_Encode_VSHL_4S ENDP

; ============================================================================
; A64_Encode_VSHR_4S: SHR Vd.4S, Vn.4S, #imm (Vector Shift Right)
;   ECX = Vd, EDX = Vn, R8D = Shift amount (1-32)
; ============================================================================
A64_Encode_VSHR_4S PROC
    ; Base Template: 0x4F001400 (USHR immediate, Q=1)
    mov eax, 04F001400h
    and ecx, 01Fh
    and edx, 01Fh
    and r8d, 03Fh
    
    mov r9d, r8d
    shl r9d, 16
    
    shl edx, 5
    or eax, ecx
    or eax, edx
    or eax, r9d
    ret
A64_Encode_VSHR_4S ENDP

END
