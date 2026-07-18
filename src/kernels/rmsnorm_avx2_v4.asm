; RMSNorm AVX2 Optimized Implementation v4
; Fixed numerical precision with direct sqrt+division
; Target: >3x speedup, <1e-5 max error
;
; Formula: y = x / sqrt(mean(x^2) + epsilon)
; Using direct sqrt and division for accuracy

.code

; extern "C" void rmsnorm_avx2_f32(
;     const float* input,
;     float* output,
;     size_t n,
;     float epsilon
; );

rmsnorm_avx2_f32 PROC FRAME
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

    mov     rdi, rcx        ; rdi = input
    mov     rsi, rdx        ; rsi = output
    mov     rbx, r8         ; rbx = n
    vbroadcastss ymm7, xmm3 ; ymm7 = epsilon (all lanes)
    
    ; Phase 1: Compute sum of squares
    vxorps  ymm0, ymm0, ymm0    ; ymm0 = accumulator
    
    mov     rbp, rbx
    shr     rbp, 3              ; rbp = n / 8
    test    rbp, rbp
    jz      @tail_sum

    ; Main sum loop - process 8 floats at a time
@loop_sum:
    vmovups ymm1, ymmword ptr [rdi]
    vmulps  ymm2, ymm1, ymm1    ; x * x
    vaddps  ymm0, ymm0, ymm2    ; Accumulate sum of squares
    add     rdi, 32
    dec     rbp
    jnz     @loop_sum

@tail_sum:
    ; Horizontal sum of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm0, xmm0
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vaddss  xmm0, xmm0, xmm1
    
    ; Handle remaining elements (n % 8)
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @compute_rms
    
@tail_loop:
    movss   xmm1, dword ptr [rdi]
    mulss   xmm1, xmm1
    addss   xmm0, xmm1
    add     rdi, 4
    dec     rbp
    jnz     @tail_loop

@compute_rms:
    ; xmm0 = sum_of_squares
    ; Compute mean = sum / n
    cvtsi2ss xmm1, ebx
    divss   xmm0, xmm1          ; xmm0 = mean
    
    ; mean + epsilon
    addss   xmm0, xmm7          ; xmm0 = mean + epsilon
    
    ; Compute sqrt directly (not rsqrt)
    sqrtss  xmm0, xmm0          ; xmm0 = sqrt(mean + epsilon) = rms
    
    ; Compute 1/rms for multiplication
    mov     rax, offset one
    movss   xmm1, dword ptr [rax]
    divss   xmm1, xmm0          ; xmm1 = 1/rms
    vbroadcastss ymm6, xmm1     ; ymm6 = 1/rms (all lanes)
    
    ; Phase 2: Normalize
    mov     rdi, rcx            ; Reset input pointer
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_normalize

    ; Main normalization loop
@loop_normalize:
    vmovups ymm1, ymmword ptr [rdi]
    vmulps  ymm1, ymm1, ymm6    ; x * (1/rms)
    vmovups ymmword ptr [rsi], ymm1
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
    
    movss   xmm6, xmm6          ; Extract scalar
    
@tail_norm_loop:
    movss   xmm1, dword ptr [rdi]
    mulss   xmm1, xmm6
    movss   dword ptr [rsi], xmm1
    add     rdi, 4
    add     rsi, 4
    dec     rbp
    jnz     @tail_norm_loop

@done:
    vzeroupper
    add     rsp, 32
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

rmsnorm_avx2_f32 ENDP

.data
ALIGN 16
one     real4 1.0

END
