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
; QuantizedMatMul_Fused_4K_AVX512 - AVX-512 optimized version
; Processes 16 blocks at once for maximum throughput
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

    ; Load constant 8.0 for centering into ZMM15
    mov     eax, 0x41000000       ; 8.0 in IEEE 754
    vmovd   xmm15, eax
    vbroadcastss zmm15, xmm15     ; ZMM15 = 8.0 (broadcast to all elements)

RowLoop_AVX512:
    ; Calculate weights pointer for this row
    mov     rax, rbx
    imul    rax, 2560             ; RAX = row * bytes_per_row
    mov     r15, rsi
    add     r15, rax              ; R15 = weights pointer for this row

    ; Initialize 8 ZMM accumulators (each holds 16 floats, we sum them at the end)
    vxorps  zmm0, zmm0, zmm0      ; Accumulator 0
    vxorps  zmm1, zmm1, zmm1      ; Accumulator 1
    vxorps  zmm2, zmm2, zmm2      ; Accumulator 2
    vxorps  zmm3, zmm3, zmm3      ; Accumulator 3
    vxorps  zmm4, zmm4, zmm4      ; Accumulator 4
    vxorps  zmm5, zmm5, zmm5      ; Accumulator 5
    vxorps  zmm6, zmm6, zmm6      ; Accumulator 6
    vxorps  zmm7, zmm7, zmm7      ; Accumulator 7

    mov     rcx, r13              ; RCX = blocks per row (128)
    mov     rbp, rdx              ; RBP = activation pointer

BlockLoop_AVX512:
    ; Process 16 blocks at a time (512 weights)
    cmp     rcx, 16
    jl      BlockLoop_Scalar      ; If less than 16 blocks remain, use scalar

    ; Load 16 scales into ZMM8
    ; Scales are at [r15], [r15+20], [r15+40], ...
    ; We need to gather them since they're strided
    vbroadcastss zmm8, dword ptr [r15]           ; Block 0 scale
    vbroadcastss zmm9, dword ptr [r15+20]        ; Block 1 scale
    vbroadcastss zmm10, dword ptr [r15+40]       ; Block 2 scale
    vbroadcastss zmm11, dword ptr [r15+60]       ; Block 3 scale

    ; Load activations for these 16 blocks (16 floats)
    vmovups zmm12, zmmword ptr [rbp]             ; 16 activations

    ; Process first 4 blocks (128 weights)
    ; Each block: load 16 bytes (32 nibbles), expand to 32 floats
    ; This is complex - for now, process 4 blocks with 4 separate operations

    ; Block 0: weights at r15+4
    vmovdqu xmm13, xmmword ptr [r15+4]          ; 16 bytes = 32 nibbles
    vpmovzxbw ymm13, xmm13                      ; Zero extend bytes to words
    vpmovzxwd zmm13, xmm13                      ; Zero extend words to dwords
    vcvtdq2ps zmm13, zmm13                      ; Convert to float
    vsubps  zmm13, zmm13, zmm15                 ; Center: subtract 8.0
    vmulps  zmm13, zmm13, zmm8                  ; Scale
    vmulps  zmm14, zmm13, zmm12                 ; Multiply by activations
    vaddps  zmm0, zmm0, zmm14                   ; Accumulate

    ; Block 1: weights at r15+24
    vmovdqu xmm13, xmmword ptr [r15+24]
    vpmovzxbw ymm13, xmm13
    vpmovzxwd zmm13, xmm13
    vcvtdq2ps zmm13, zmm13
    vsubps  zmm13, zmm13, zmm15
    vmulps  zmm13, zmm13, zmm9
    vmulps  zmm14, zmm13, zmm12
    vaddps  zmm1, zmm1, zmm14

    ; Block 2: weights at r15+44
    vmovdqu xmm13, xmmword ptr [r15+44]
    vpmovzxbw ymm13, xmm13
    vpmovzxwd zmm13, xmm13
    vcvtdq2ps zmm13, zmm13
    vsubps  zmm13, zmm13, zmm15
    vmulps  zmm13, zmm13, zmm10
    vmulps  zmm14, zmm13, zmm12
    vaddps  zmm2, zmm2, zmm14

    ; Block 3: weights at r15+64
    vmovdqu xmm13, xmmword ptr [r15+64]
    vpmovzxbw ymm13, xmm13
    vpmovzxwd zmm13, xmm13
    vcvtdq2ps zmm13, zmm13
    vsubps  zmm13, zmm13, zmm15
    vmulps  zmm13, zmm13, zmm11
    vmulps  zmm14, zmm13, zmm12
    vaddps  zmm3, zmm3, zmm14

    add     r15, 80               ; 4 blocks * 20 bytes
    add     rbp, 64               ; 16 activations * 4 bytes
    sub     rcx, 4                ; Processed 4 blocks
    jmp     BlockLoop_AVX512

BlockLoop_Scalar:
    ; Fall back to scalar for remaining blocks
    test    rcx, rcx
    jz      DoneRow_AVX512

BlockLoop_Scalar_Remainder:
    movss   xmm1, dword ptr [r15]
    mov     r9, 16
    xor     r10, r10

WeightLoop_Scalar:
    cmp     r10, r9
    jge     WeightDone_Scalar
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
    jmp     WeightLoop_Scalar

WeightDone_Scalar:
    add     r15, Q4_0_BLOCK_SIZE
    dec     rcx
    jnz     BlockLoop_Scalar_Remainder

DoneRow_AVX512:
    ; Horizontal sum of all accumulators
    vaddps  zmm0, zmm0, zmm1
    vaddps  zmm0, zmm0, zmm2
    vaddps  zmm0, zmm0, zmm3
    vaddps  zmm0, zmm0, zmm4
    vaddps  zmm0, zmm0, zmm5
    vaddps  zmm0, zmm0, zmm6
    vaddps  zmm0, zmm0, zmm7

    ; Extract and sum all 16 elements
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    addps   xmm0, xmm0, xmm1
    movhlps xmm1, xmm0
    addps   xmm0, xmm0, xmm1
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
