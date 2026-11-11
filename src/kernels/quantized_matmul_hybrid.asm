;===========================================================================
; quantized_matmul_hybrid.asm - Hybrid AVX-512 Implementation
; Stage: Inline validated dequant -> immediate FMA (no full materialization)
;===========================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC QuantizedMatMul_Fused_4K_Hybrid

.CODE

;=============================================================================
; QuantizedMatMul_Fused_4K_Hybrid - Hybrid Dequant + FMA
; Inlines validated AVX-512 dequant logic with immediate FMA consumption
; No function calls - all operations are register-to-register
;=============================================================================
QuantizedMatMul_Fused_4K_Hybrid PROC FRAME
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rbp
    .pushreg rdi
    .pushreg rsi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    mov     rsi, rcx              ; RSI = weights
    mov     rdi, r8               ; RDI = output
    mov     r12, 4096             ; N = 4096
    mov     r13, 128              ; blocks per row (4096/32)

    mov     r14, rdi              ; R14 = output pointer
    xor     rbx, rbx              ; RBX = row index
    
    ; Precompute constants in ZMM registers
    ; ZMM30 = 8.0 (zero-point for subtraction)
    mov     eax, 41000000h        ; 8.0 in IEEE 754
    vmovd   xmm29, eax
    vbroadcastss zmm30, xmm29     ; ZMM30 = 8.0 (16 floats)
    
    ; ZMM29 = 0x0F (nibble mask)
    mov     eax, 0F0F0F0Fh
    vmovd   xmm28, eax
    vbroadcastss zmm29, xmm28     ; ZMM29 = 0x0F0F0F0F

RowLoop_Hybrid:
    ; Calculate weights pointer for this row
    mov     rax, rbx
    imul    rax, 2560             ; RAX = row * bytes_per_row
    mov     r15, rsi
    add     r15, rax              ; R15 = weights pointer for this row

    ; Initialize ZMM accumulator
    vxorps  zmm0, zmm0, zmm0      ; ZMM0 = accumulator (16 floats)

    mov     rcx, r13              ; RCX = blocks per row (128)
    mov     rbp, rdx              ; RBP = activation pointer

BlockLoop_Hybrid:
    cmp     rcx, 1
    jl      DoneRow_Hybrid        ; No blocks left

    ; === Stage 1: Inline AVX-512 Dequant ===
    ; Load scale and broadcast
    vbroadcastss zmm1, dword ptr [r15]       ; ZMM1 = scale
    
    ; Load 16 bytes (32 nibbles)
    vmovdqu xmm2, xmmword ptr [r15+4]        ; XMM2 = packed weights
    
    ; Zero-extend bytes to dwords
    vpmovzxbd zmm2, xmm2                     ; ZMM2 = 16 dwords
    
    ; Extract lower nibbles
    vpandd  zmm3, zmm2, zmm29                ; ZMM3 = lower nibbles
    
    ; Extract upper nibbles
    vpsrld  zmm4, zmm2, 4
    vpandd  zmm4, zmm4, zmm29                ; ZMM4 = upper nibbles
    
    ; Zero-point correction
    vpsubd  zmm3, zmm3, zmm30                ; ZMM3 = lower - 8
    vpsubd  zmm4, zmm4, zmm30                ; ZMM4 = upper - 8
    
    ; Convert to float and scale
    vcvtdq2ps zmm3, zmm3                     ; ZMM3 = float(lower - 8)
    vcvtdq2ps zmm4, zmm4                     ; ZMM4 = float(upper - 8)
    vmulps  zmm3, zmm3, zmm1                 ; ZMM3 = scaled lower
    vmulps  zmm4, zmm4, zmm1                 ; ZMM4 = scaled upper
    
    ; === Stage 2: Immediate FMA (no memory traffic) ===
    ; Load activations
    vmovups zmm5, zmmword ptr [rbp]          ; ZMM5 = activations 0-15
    vmovups zmm6, zmmword ptr [rbp+64]       ; ZMM6 = activations 16-31
    
    ; FMA: accumulator += dequantized * activation
    vfmadd231ps zmm0, zmm3, zmm5             ; ZMM0 += lower_weights * act_low
    vfmadd231ps zmm0, zmm4, zmm6             ; ZMM0 += upper_weights * act_high

    add     r15, 20               ; Next block (20 bytes)
    add     rbp, 128              ; 32 weights * 4 bytes
    dec     rcx
    jmp     BlockLoop_Hybrid

DoneRow_Hybrid:
    ; Horizontal sum of ZMM0 into scalar output
    vextractf64x4 ymm1, zmm0, 1             ; Extract high 256 bits
    vaddps  ymm0, ymm0, ymm1                ; Add high and low halves
    vextractf128 xmm1, ymm0, 1              ; Extract high 128 bits
    vaddps  xmm0, xmm0, xmm1                ; Add
    vmovhlps xmm1, xmm0, xmm0              ; Move high half to low
    vaddps  xmm0, xmm0, xmm1                ; Add
    vshufps xmm1, xmm0, xmm0, 1             ; Rotate
    vaddss  xmm0, xmm0, xmm1                ; Final add
    vmovss  dword ptr [r14], xmm0

    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_Hybrid

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1
    ret
QuantizedMatMul_Fused_4K_Hybrid ENDP

END
