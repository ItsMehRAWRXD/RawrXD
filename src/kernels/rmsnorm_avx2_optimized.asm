; RMSNorm AVX2 Optimized Implementation
; Target: 2.5x+ speedup over scalar reference
; Author: RawrXD Optimization Team
; Date: 2026-07-17

; RMSNorm: x * rsqrt(mean(x^2) + epsilon)
; Optimizations:
;   - 256-bit AVX2 vectorization (8 floats per iteration)
;   - Parallel sum-of-squares computation
;   - Fast reciprocal square root approximation
;   - Aligned memory access (32-byte boundaries)

.code

; extern "C" void rmsnorm_avx2_f32(
;     const float* input,      ; rcx
;     float* output,           ; rdx
;     size_t n,                ; r8
;     float epsilon            ; xmm3 (lower 32 bits)
; );

rmsnorm_avx2_f32 PROC FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Arguments:
    ; rcx = input pointer
    ; rdx = output pointer
    ; r8  = n (number of elements)
    ; xmm3 = epsilon (scalar float)

    mov     rdi, rcx        ; rdi = input
    mov     rsi, rdx        ; rsi = output
    mov     rbx, r8         ; rbx = n
    
    ; Broadcast epsilon to all lanes
    vbroadcastss ymm7, xmm3
    
    ; Initialize accumulators for sum-of-squares
    vxorps  ymm0, ymm0, ymm0    ; ymm0 = 0 (sum accumulator)
    
    ; Calculate main loop count (n / 8)
    mov     rbp, rbx
    shr     rbp, 3              ; rbp = n / 8
    
    ; Check if we have at least 8 elements
    test    rbp, rbp
    jz      @F                  ; Skip main loop if n < 8

    ; Main loop: process 8 floats at a time
    ALIGN 16
@loop_sum:
    vmovaps ymm1, [rdi]         ; Load 8 floats
    vmulps  ymm2, ymm1, ymm1    ; Square each element
    vaddps  ymm0, ymm0, ymm2    ; Accumulate sum of squares
    add     rdi, 32             ; Advance input pointer
    dec     rbp
    jnz     @loop_sum

@@:
    ; Horizontal sum of ymm0 to get total sum-of-squares
    ; Use vhaddps approach for better throughput
    vextractf128 xmm1, ymm0, 1  ; Extract high 128 bits
    vaddps  xmm0, xmm0, xmm1    ; Add high and low
    vhaddps xmm0, xmm0, xmm0    ; Horizontal add
    vhaddps xmm0, xmm0, xmm0    ; Final horizontal add
    
    ; xmm0 now contains sum-of-squares
    
    ; Handle remaining elements (n % 8)
    mov     rbp, rbx
    and     rbp, 7              ; rbp = n % 8
    test    rbp, rbp
    jz      @compute_rms
    
    ; Process remaining elements (scalar)
    xorps   xmm2, xmm2          ; xmm2 = accumulator for tail
@tail_loop:
    movss   xmm3, [rdi]
    mulss   xmm3, xmm3
    addss   xmm2, xmm3
    add     rdi, 4
    dec     rbp
    jnz     @tail_loop
    
    ; Add tail sum to main sum
    addss   xmm0, xmm2

@compute_rms:
    ; xmm0 = sum_of_squares
    ; Compute rms = sqrt(sum_of_squares / n + epsilon)
    
    ; Convert n to float
    cvtsi2ss xmm1, rbx          ; xmm1 = float(n)
    
    ; mean = sum_of_squares / n
    divss   xmm0, xmm1          ; xmm0 = mean
    
    ; mean + epsilon
    addss   xmm0, xmm7          ; xmm0 = mean + epsilon
    
    ; rsqrt(mean + epsilon) - use fast approximation
    rsqrtss xmm0, xmm0          ; xmm0 = 1/sqrt(mean + epsilon)
    
    ; Broadcast rms to all lanes
    vbroadcastss ymm6, xmm0     ; ymm6 = rms (all lanes)
    
    ; Reset input pointer for normalization pass
    mov     rdi, rcx
    
    ; Calculate main loop count again
    mov     rbp, rbx
    shr     rbp, 3
    
    ; Check if we have at least 8 elements
    test    rbp, rbp
    jz      @tail_normalize

    ; Main normalization loop
    ALIGN 16
@loop_normalize:
    vmovaps ymm1, [rdi]         ; Load input
    vmulps  ymm1, ymm1, ymm6    ; Multiply by rms
    vmovaps [rsi], ymm1         ; Store output
    add     rdi, 32
    add     rsi, 32
    dec     rbp
    jnz     @loop_normalize

@tail_normalize:
    ; Handle remaining elements
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @done
    
    ; Extract scalar rms from ymm6
    movss   xmm6, xmm6
    
@tail_norm_loop:
    movss   xmm1, [rdi]
    mulss   xmm1, xmm6
    movss   [rsi], xmm1
    add     rdi, 4
    add     rsi, 4
    dec     rbp
    jnz     @tail_norm_loop

@done:
    ; Restore stack and registers
    vzeroupper
    add     rsp, 32
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

rmsnorm_avx2_f32 ENDP

; extern "C" void rmsnorm_avx2_f32_aligned(
;     const float* input,      ; rcx (32-byte aligned)
;     float* output,           ; rdx (32-byte aligned)
;     size_t n,                ; r8 (multiple of 8)
;     float epsilon            ; xmm3
; );

rmsnorm_avx2_f32_aligned PROC FRAME
    ; Optimized version for aligned memory and n % 8 == 0
    ; No tail handling needed
    
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    sub     rsp, 16
    .allocstack 16
    .endprolog

    mov     r9, rcx             ; r9 = input
    mov     r10, rdx            ; r10 = output
    mov     rbp, r8             ; rbp = n
    vbroadcastss ymm7, xmm3     ; ymm7 = epsilon
    
    ; Sum-of-squares phase
    vxorps  ymm0, ymm0, ymm0    ; Accumulator
    mov     rbx, rbp
    shr     rbx, 3              ; rbx = n / 8

    ALIGN 16
@sum_loop:
    vmovaps ymm1, [r9 + rbx*8 - 32]  ; Load with negative offset
    vfmadd231ps ymm0, ymm1, ymm1     ; Fused multiply-add
    dec     rbx
    jnz     @sum_loop
    
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Compute rms
    cvtsi2ss xmm1, rbp
    divss   xmm0, xmm1
    addss   xmm0, xmm7
    rsqrtss xmm0, xmm0
    vbroadcastss ymm6, xmm0
    
    ; Normalization phase
    mov     rbx, rbp
    shr     rbx, 3

    ALIGN 16
@norm_loop:
    vmovaps ymm1, [r9 + rbx*8 - 32]
    vmulps  ymm1, ymm1, ymm6
    vmovaps [r10 + rbx*8 - 32], ymm1
    dec     rbx
    jnz     @norm_loop

    vzeroupper
    add     rsp, 16
    pop     rbp
    pop     rbx
    ret

rmsnorm_avx2_f32_aligned ENDP

END
