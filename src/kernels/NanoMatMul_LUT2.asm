;============================================================================
; NanoMatMul_LUT2.asm - RawrXD Brutal Compression Kernel
; LUT-2 (2-bit) Matrix Multiplication with Inline Bit-Unpacking
; AVX-512, x64, Zero Dependencies
;============================================================================

.code

;----------------------------------------------------------------------------
; BitUnpack_2bit - Unpack 256 x 2-bit indices to 256 x 32-bit
; Input:  RCX = pointer to 64 bytes of packed 2-bit data
; Output: ZMM0-ZMM3 = 256 unpacked 32-bit indices (0-3)
; Clobbers: ZMM4-ZMM7, RAX, RDX
;----------------------------------------------------------------------------
BitUnpack_2bit PROC
    ; Load 64 bytes (256 x 2-bit indices packed)
    vmovdqu64 zmm4, [rcx]
    
    ; Extract indices 0-15 (bits 0-31 of each dword)
    ; Shift right by 0, 2, 4, 6...30 within each 32-bit lane
    vpsrlvd zmm0, zmm4, [rel shift_0_15]
    vpandd  zmm0, zmm0, [rel mask_3]
    
    ; Extract indices 16-31
    vpsrlvd zmm1, zmm4, [rel shift_16_31]
    vpandd  zmm1, zmm1, [rel mask_3]
    
    ; Extract indices 32-47
    vpsrlvd zmm2, zmm4, [rel shift_32_47]
    vpandd  zmm2, zmm2, [rel mask_3]
    
    ; Extract indices 48-63
    vpsrlvd zmm3, zmm4, [rel shift_48_63]
    vpandd  zmm3, zmm3, [rel mask_3]
    
    ret
BitUnpack_2bit ENDP

;----------------------------------------------------------------------------
; NanoMatMul_LUT2 - Matrix multiply with 2-bit compressed weights
; RCX = packed weight indices (z) - 64 bytes
; RDX = activations - 256 floats (1024 bytes)
; R8  = output accumulator - 256 floats
; R9  = codebook pointer (4 x float: values for indices 0,1,2,3)
; R10 = number of elements (must be multiple of 256)
;----------------------------------------------------------------------------
public NanoMatMul_LUT2
NanoMatMul_LUT2 PROC
    push    rbx
    push    r12
    push    r13
    
    ; Load codebook into ZMM registers (broadcast 4 values)
    vbroadcastss zmm10, dword ptr [r9]        ; Index 0 value
    vbroadcastss zmm11, dword ptr [r9+4]      ; Index 1 value
    vbroadcastss zmm12, dword ptr [r9+8]      ; Index 2 value
    vbroadcastss zmm13, dword ptr [r9+12]     ; Index 3 value
    
    ; Zero accumulator
    vxorps  zmm15, zmm15, zmm15
    
    mov     r12, r10                          ; Element counter
    mov     r13, rcx                          ; Weight pointer
    mov     rbx, rdx                          ; Activation pointer

.loop_start:
    ; Unpack 256 indices (64 bytes -> 256 x 32-bit in ZMM0-ZMM3)
    mov     rcx, r13
    call    BitUnpack_2bit
    
    ; Process first 64 elements (ZMM0)
    vmovups zmm5, [rbx]                       ; Load 16 activations
    
    ; Lookup weights using blend (faster than gather for 4-entry codebook)
    ; zmm14 = blend of zmm10-zmm13 based on indices in zmm0
    vcmpps  k1, zmm0, [rel const_0], 0        ; Index == 0?
    vcmpps  k2, zmm0, [rel const_1], 0        ; Index == 1?
    vcmpps  k3, zmm0, [rel const_2], 0        ; Index == 2?
    
    vmovaps zmm14, zmm13                      ; Start with index 3 (default)
    vmovaps zmm14 {k3}, zmm12                ; Blend index 2 where mask
    vmovaps zmm14 {k2}, zmm11                ; Blend index 1 where mask
    vmovaps zmm14 {k1}, zmm10                ; Blend index 0 where mask
    
    vfmadd231ps zmm15, zmm14, zmm5            ; Accumulate
    
    ; Process next 64 elements (ZMM1)
    vmovups zmm5, [rbx+64]
    
    vcmpps  k1, zmm1, [rel const_0], 0
    vcmpps  k2, zmm1, [rel const_1], 0
    vcmpps  k3, zmm1, [rel const_2], 0
    
    vmovaps zmm14, zmm13
    vmovaps zmm14 {k3}, zmm12
    vmovaps zmm14 {k2}, zmm11
    vmovaps zmm14 {k1}, zmm10
    
    vfmadd231ps zmm15, zmm14, zmm5
    
    ; Process next 64 elements (ZMM2)
    vmovups zmm5, [rbx+128]
    
    vcmpps  k1, zmm2, [rel const_0], 0
    vcmpps  k2, zmm2, [rel const_1], 0
    vcmpps  k3, zmm2, [rel const_2], 0
    
    vmovaps zmm14, zmm13
    vmovaps zmm14 {k3}, zmm12
    vmovaps zmm14 {k2}, zmm11
    vmovaps zmm14 {k1}, zmm10
    
    vfmadd231ps zmm15, zmm14, zmm5
    
    ; Process last 64 elements (ZMM3)
    vmovups zmm5, [rbx+192]
    
    vcmpps  k1, zmm3, [rel const_0], 0
    vcmpps  k2, zmm3, [rel const_1], 0
    vcmpps  k3, zmm3, [rel const_2], 0
    
    vmovaps zmm14, zmm13
    vmovaps zmm14 {k3}, zmm12
    vmovaps zmm14 {k2}, zmm11
    vmovaps zmm14 {k1}, zmm10
    
    vfmadd231ps zmm15, zmm14, zmm5
    
    ; Advance pointers
    add     r13, 64                           ; Next 64 bytes of packed weights
    add     rbx, 256                          ; Next 256 floats of activations
    sub     r12, 256                          ; Decrement counter
    ja      .loop_start
    
    ; Store result
    vmovups [r8], zmm15
    
    pop     r13
    pop     r12
    pop     rbx
    vzeroupper
    ret
NanoMatMul_LUT2 ENDP

;----------------------------------------------------------------------------
; NanoMatMul_XNOR - 0.5-bit (binary) matrix multiplication
; RCX = packed binary weights (1 bit per weight) - 32 bytes for 256 weights
; RDX = binary activations (1 bit per activation) - 32 bytes
; R8  = output (single float result)
; R9  = number of elements (must be multiple of 512)
;----------------------------------------------------------------------------
public NanoMatMul_XNOR
NanoMatMul_XNOR PROC
    push    rbx
    push    r12
    
    vxorps  zmm0, zmm0, zmm0                  ; Zero accumulator
    
    mov     r12, r9                           ; Counter
    mov     rbx, rcx                          ; Weight pointer
    mov     rax, rdx                          ; Activation pointer

.xnor_loop:
    ; Load 512 bits (64 bytes) of packed weights
    vmovdqu64 zmm1, [rbx]
    
    ; Load 512 bits of packed activations
    vmovdqu64 zmm2, [rax]
    
    ; XNOR: equivalent to multiplication for {-1, +1}
    ; XNOR(A,B) = NOT(A XOR B)
    vpxorq  zmm3, zmm1, zmm2
    vpcmpeqb zmm3, zmm3, [rel all_ones]       ; XNOR result
    
    ; Popcount to sum (AVX-512 VPOPCNTDQ)
    vpopcntq zmm4, zmm3
    
    ; Accumulate
    vpaddq  zmm0, zmm0, zmm4
    
    ; Advance
    add     rbx, 64
    add     rax, 64
    sub     r12, 512
    ja      .xnor_loop
    
    ; Horizontal sum of zmm0
    vextracti64x2 xmm1, zmm0, 3
    vextracti64x2 xmm2, zmm0, 2
    vextracti64x2 xmm3, zmm0, 1
    
    paddq   xmm0, xmm1
    paddq   xmm0, xmm2
    paddq   xmm0, xmm3
    
    ; Convert to float and store
    vcvtsi2ss xmm0, xmm0, xmm0
    vmovss  dword ptr [r8], xmm0
    
    pop     r12
    pop     rbx
    vzeroupper
    ret
NanoMatMul_XNOR ENDP

;----------------------------------------------------------------------------
; Data Section - Constants
;----------------------------------------------------------------------------
.data

align 64
shift_0_15:     dd 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30
shift_16_31:    dd 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30
shift_32_47:    dd 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30
shift_48_63:    dd 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30
mask_3:         dd 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
const_0:        dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
const_1:        dd 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
const_2:        dd 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
all_ones:       db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255
                db 255, 255, 255, 255, 255, 255, 255, 255

END
