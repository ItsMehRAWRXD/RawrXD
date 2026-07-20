;===========================================================================
; quantized_matmul.asm - Minimal Working Implementation
; RawrXD Fix #4 - Fused Q4_0 Dequant + MatMul
;===========================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

Q4_0_BLOCK_SIZE EQU 20

PUBLIC QuantizedMatMul_Fused_4K
PUBLIC QuantizedMatMul_Fused_4K_AVX512
PUBLIC QuantizedMatMul_Fused_5K
PUBLIC QuantizedMatMul_Dynamic
PUBLIC RawrXD_QuantizedMatMul_Dispatch
PUBLIC RawrXD_KernelRegistry_Init
PUBLIC RawrXD_KernelTelemetry_Begin
PUBLIC RawrXD_KernelTelemetry_End

;=============================================================================
; Constant Data
;=============================================================================
.DATA
ALIGN 32
low_nibble_mask WORD 16 DUP (0Fh)    ; 16 words of 0x0F for nibble masking
zero_point DWORD 8                     ; Zero-point value (8)

.CODE

;=============================================================================
; QuantizedMatMul_Fused_4K - Minimal scalar implementation
;=============================================================================
QuantizedMatMul_Fused_4K PROC FRAME
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
    mov     r12, 4096             ; N = 4096 (use 64-bit register)
    mov     r13, 128              ; blocks per row (4096/32)

    mov     r14, rdi              ; R14 = output pointer
    xor     rbx, rbx              ; RBX = row index

RowLoop:
    ; Calculate weights pointer for this row: weights + row * bytes_per_row
    ; bytes_per_row = blocks_per_row * block_size = 128 * 20 = 2560
    mov     rax, rbx
    imul    rax, 2560             ; RAX = row * bytes_per_row
    mov     r15, rsi
    add     r15, rax              ; R15 = weights pointer for this row (non-volatile!)
    
    vxorps  xmm0, xmm0, xmm0      ; Clear scalar accumulator
    mov     rcx, r13              ; RCX = blocks per row
    mov     rbp, rdx              ; RBP = activation pointer (reset for each row)

BlockLoop:
    ; Load scale
    movss   xmm1, dword ptr [r15]
    
    ; Process 32 weights in this block
    ; r15 points to current block, weights data is at r15+4
    mov     r9, 16                ; R9 = 16 bytes (32 nibbles)
    xor     r10, r10              ; R10 = byte index

WeightLoop:
    cmp     r10, r9
    jge     WeightDone
    
    ; Load byte containing 2 weights (r15+4 is weights data, +r10 is byte offset)
    movzx   r11d, byte ptr [r15 + 4 + r10]
    
    ; Process lower nibble (weight 0) - use eax as temp
    mov     eax, r11d
    and     eax, 0Fh              ; Lower 4 bits
    sub     eax, 8                ; Center: 0-15 to -8 to +7
    cvtsi2ss xmm2, eax            ; Convert to float
    mulss   xmm2, xmm1            ; Scale
    movss   xmm3, dword ptr [rbp] ; Load activation[0]
    mulss   xmm2, xmm3            ; Multiply
    addss   xmm0, xmm2            ; Accumulate
    
    ; Process upper nibble (weight 1)
    mov     eax, r11d
    shr     eax, 4                ; Upper 4 bits
    and     eax, 0Fh
    sub     eax, 8                ; Center
    cvtsi2ss xmm2, eax            ; Convert to float
    mulss   xmm2, xmm1            ; Scale
    movss   xmm3, dword ptr [rbp + 4] ; Load activation[1]
    mulss   xmm2, xmm3            ; Multiply
    addss   xmm0, xmm2            ; Accumulate
    
    add     rbp, 8                ; 2 activations * 4 bytes
    inc     r10
    jmp     WeightLoop

WeightDone:
    add     r15, Q4_0_BLOCK_SIZE  ; Next block
    dec     rcx
    jnz     BlockLoop
    
    ; Store result
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop

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
QuantizedMatMul_Fused_4K ENDP

;=============================================================================
;=============================================================================
; QuantizedMatMul_Fused_4K_AVX512 - Fully Vectorized AVX-512 Implementation
; Processes 64 weights (2 blocks) per iteration using ZMM registers
; Target: 2,000+ TPS through pipelined vectorization
;=============================================================================
QuantizedMatMul_Fused_4K_AVX512 PROC FRAME
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

    ; Precompute constants
    ; ZMM31 = 8.0 (zero-point centering constant)
    mov     eax, 41000000h        ; 8.0 in IEEE 754
    vmovd   xmm30, eax
    vbroadcastss zmm31, xmm30     ; ZMM31 = 8.0 (16 floats)
    
    ; ZMM30 = 0x0F (nibble mask as float for bitwise ops compatibility)
    ; Actually we need integer mask, let's use different approach

RowLoop_AVX512:
    ; Calculate weights pointer for this row
    mov     rax, rbx
    imul    rax, 2560             ; RAX = row * bytes_per_row
    mov     r15, rsi
    add     r15, rax              ; R15 = weights pointer for this row

    ; Initialize accumulator
    vxorps  zmm0, zmm0, zmm0      ; ZMM0 = accumulator (16 floats)

    mov     rcx, r13              ; RCX = blocks per row (128)
    mov     rbp, rdx              ; RBP = activation pointer (reset for each row)

BlockLoop_AVX512:
    cmp     rcx, 2
    jl      BlockLoop_Scalar_AVX512

    ; Process 2 blocks (64 weights) using vectorized unpacking
    
    ; Load scale for both blocks
    vbroadcastss zmm1, dword ptr [r15]       ; ZMM1 = scale0
    vbroadcastss zmm2, dword ptr [r15+20]    ; ZMM2 = scale1

    ; === Process Block 0, Weights 0-15 (16 bytes at r15+4) ===
    ; Load 16 bytes into XMM3
    vmovdqu xmm3, xmmword ptr [r15+4]
    
    ; Unpack to 16 words in YMM3
    vpmovzxbw ymm3, xmm3
    
    ; Split low/high nibbles
    ; Low: AND with 0x0F
    vpand   ymm4, ymm3, ymmword ptr [low_nibble_mask]
    ; High: Shift right 4, then AND
    vpsrlw  ymm5, ymm3, 4
    vpand   ymm5, ymm5, ymmword ptr [low_nibble_mask]
    
    ; Convert words to dwords, then to float
    vpmovzxwd zmm4, ymm4         ; Low nibbles as dwords
    vpmovzxwd zmm5, ymm5         ; High nibbles as dwords
    
    ; Subtract zero-point (8)
    vpbroadcastd zmm6, dword ptr [zero_point]
    vpsubd  zmm4, zmm4, zmm6
    vpsubd  zmm5, zmm5, zmm6
    
    ; Convert to float
    vcvtdq2ps zmm4, zmm4
    vcvtdq2ps zmm5, zmm5
    
    ; Scale
    vmulps  zmm4, zmm4, zmm1
    vmulps  zmm5, zmm5, zmm1
    
    ; Load activations and FMA
    vmovups zmm7, zmmword ptr [rbp]
    vmovups zmm8, zmmword ptr [rbp+64]
    vfmadd231ps zmm0, zmm4, zmm7
    vfmadd231ps zmm0, zmm5, zmm8

    ; === Process Block 0, Weights 16-31 ===
    ; Same pattern for second half of block 0
    vmovdqu xmm3, xmmword ptr [r15+4]
    ; Actually we already processed all 16 bytes above
    ; Each block has 16 bytes = 32 nibbles = 32 weights
    ; We processed 16 weights (low nibbles) + 16 weights (high nibbles)
    ; So block 0 is done, move to block 1

    ; === Process Block 1 ===
    vmovdqu xmm3, xmmword ptr [r15+24]       ; Block 1 weights at offset 24 (20+4)
    vpmovzxbw ymm3, xmm3
    
    vpand   ymm4, ymm3, ymmword ptr [low_nibble_mask]
    vpsrlw  ymm5, ymm3, 4
    vpand   ymm5, ymm5, ymmword ptr [low_nibble_mask]
    
    vpmovzxwd zmm4, ymm4
    vpmovzxwd zmm5, ymm5
    
    vpsubd  zmm4, zmm4, zmm6
    vpsubd  zmm5, zmm5, zmm6
    
    vcvtdq2ps zmm4, zmm4
    vcvtdq2ps zmm5, zmm5
    
    vmulps  zmm4, zmm4, zmm2
    vmulps  zmm5, zmm5, zmm2
    
    vmovups zmm7, zmmword ptr [rbp+128]
    vmovups zmm8, zmmword ptr [rbp+192]
    vfmadd231ps zmm0, zmm4, zmm7
    vfmadd231ps zmm0, zmm5, zmm8

    add     r15, 40               ; 2 blocks * 20 bytes
    add     rbp, 256              ; 64 weights * 4 bytes
    sub     rcx, 2
    jmp     BlockLoop_AVX512

BlockLoop_Scalar_AVX512:
    test    rcx, rcx
    jz      DoneRow_AVX512

    movss   xmm1, dword ptr [r15]
    xor     r10, r10

WeightLoop_Scalar_AVX512:
    cmp     r10, 16
    jge     WeightDone_Scalar_AVX512
    movzx   r11d, byte ptr [r15 + 4 + r10]

    mov     eax, r11d
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2

    mov     eax, r11d
    shr     eax, 4
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp + 4]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2

    add     rbp, 8
    inc     r10
    jmp     WeightLoop_Scalar_AVX512

WeightDone_Scalar_AVX512:
    add     r15, 20
    dec     rcx
    jmp     BlockLoop_Scalar_AVX512

DoneRow_AVX512:
    ; Horizontal sum
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    movhlps xmm1, xmm0
    addps   xmm0, xmm0, xmm1
    shufps  xmm1, xmm0, 1
    addss   xmm0, xmm0, xmm1
    movss   dword ptr [r14], xmm0

    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_AVX512

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
QuantizedMatMul_Fused_4K_AVX512 ENDP

QuantizedMatMul_Fused_5K PROC FRAME
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

    mov     rsi, rcx
    mov     rdi, r8
    mov     r12, 5120
    mov     r13, 160

    mov     r14, rdi
    mov     r15, rsi
    xor     rbx, rbx

RowLoop_5K:
    vxorps  xmm0, xmm0, xmm0
    mov     rcx, r13
    mov     rbp, rdx

BlockLoop_5K:
    movss   xmm1, dword ptr [r15]
    mov     r8, r15
    add     r8, 4
    mov     r9, 16
    xor     r10, r10

WeightLoop_5K:
    cmp     r10, r9
    jge     WeightDone_5K
    movzx   r11d, byte ptr [r8 + r10]
    mov     eax, r11d
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    mov     eax, r11d
    shr     eax, 4
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp + 4]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    add     rbp, 8
    inc     r10
    jmp     WeightLoop_5K

WeightDone_5K:
    add     r15, Q4_0_BLOCK_SIZE
    dec     rcx
    jnz     BlockLoop_5K
    
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_5K

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
QuantizedMatMul_Fused_5K ENDP

QuantizedMatMul_Dynamic PROC FRAME
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

    mov     rsi, rcx
    mov     rdi, r8
    mov     r12, r9
    mov     r13, qword ptr [rsp+72]
    mov     rax, r13
    shr     rax, 5
    mov     r13, rax

    mov     r14, rdi
    mov     r15, rsi
    xor     rbx, rbx

test    r12, r12
    jz      Dynamic_Done

RowLoop_Dyn:
    vxorps  xmm0, xmm0, xmm0
    mov     rcx, r13
    mov     rbp, rdx

test    rcx, rcx
    jz      RowDone_Dyn

BlockLoop_Dyn:
    movss   xmm1, dword ptr [r15]
    mov     r8, r15
    add     r8, 4
    mov     r9, 16
    xor     r10, r10

WeightLoop_Dyn:
    cmp     r10, r9
    jge     WeightDone_Dyn
    movzx   r11d, byte ptr [r8 + r10]
    mov     eax, r11d
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    mov     eax, r11d
    shr     eax, 4
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp + 4]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    add     rbp, 8
    inc     r10
    jmp     WeightLoop_Dyn

WeightDone_Dyn:
    add     r15, Q4_0_BLOCK_SIZE
    dec     rcx
    jnz     BlockLoop_Dyn

RowDone_Dyn:
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_Dyn

Dynamic_Done:
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
QuantizedMatMul_Dynamic ENDP

RawrXD_QuantizedMatMul_Dispatch PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    mov     rax, r9
    shr     rax, 10
    dec     rax
    cmp     rax, 7
    ja      Dispatch_Fallback
    cmp     rax, 3
    je      Dispatch_4K
    cmp     rax, 4
    je      Dispatch_5K
Dispatch_Fallback:
    pop     rbx
    jmp     QuantizedMatMul_Dynamic
Dispatch_4K:
    pop     rbx
    jmp     QuantizedMatMul_Fused_4K
Dispatch_5K:
    pop     rbx
    jmp     QuantizedMatMul_Fused_5K
RawrXD_QuantizedMatMul_Dispatch ENDP

RawrXD_KernelRegistry_Init PROC
    mov     rax, 1
    ret
RawrXD_KernelRegistry_Init ENDP

RawrXD_KernelTelemetry_Begin PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
RawrXD_KernelTelemetry_Begin ENDP

RawrXD_KernelTelemetry_End PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
RawrXD_KernelTelemetry_End ENDP

END
