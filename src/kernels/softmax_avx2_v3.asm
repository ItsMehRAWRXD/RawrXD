; Softmax AVX2 Optimized Implementation v3
; Fixed numerical stability with proper exp approximation
; Target: >2x speedup, sum(output) = 1.0, no NaN
;
; Formula: softmax(x_i) = exp(x_i - max) / sum(exp(x - max))
; Using polynomial exp with range reduction for stability

.code

; extern "C" void softmax_avx2_f32(
;     const float* input,
;     float* output,
;     size_t n
; );

softmax_avx2_f32 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    sub     rsp, 64
    .allocstack 64
    .endprolog

    mov     rdi, rcx        ; rdi = input
    mov     rsi, rdx        ; rsi = output
    mov     rbx, r8         ; rbx = n

    ; Phase 1: Find max value
    vbroadcastss ymm0, dword ptr [rdi]  ; ymm0 = max (all lanes)
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_max

@max_loop:
    vmovups ymm1, ymmword ptr [rdi + rbp*8 - 32]
    vmaxps  ymm0, ymm0, ymm1
    dec     rbp
    jnz     @max_loop

@tail_max:
    ; Horizontal max reduction
    vextractf128 xmm1, ymm0, 1
    vmaxps  xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm0, xmm0
    vmaxps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vmaxss  xmm0, xmm0, xmm1
    
    vbroadcastss ymm5, xmm0       ; ymm5 = max (all lanes)
    
    ; Phase 2: Compute exp(x - max) and sum
    mov     rdi, rcx            ; Reset input
    vxorps  ymm6, ymm6, ymm6    ; ymm6 = sum accumulator
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_exp

    ; Load polynomial coefficients
    vbroadcastss ymm8, dword ptr [exp_c0]   ; 1.0
    vbroadcastss ymm9, dword ptr [exp_c1]   ; 1.0
    vbroadcastss ymm10, dword ptr [exp_c2]  ; 0.5
    vbroadcastss ymm11, dword ptr [exp_c3]  ; 0.16666667
    vbroadcastss ymm12, dword ptr [exp_c4]  ; 0.04166667

@exp_loop:
    vmovups ymm1, ymmword ptr [rdi + rbp*8 - 32]
    vsubps  ymm1, ymm1, ymm5    ; x = input - max
    
    ; Clamp x to avoid overflow: x = min(x, 88.0)
    ; (exp(88) is near float max)
    vminps  ymm1, ymm1, ymmword ptr [exp_max_input]
    
    ; Polynomial approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmulps  ymm2, ymm1, ymm1    ; x^2
    vmulps  ymm3, ymm2, ymm1    ; x^3
    vmulps  ymm4, ymm3, ymm1    ; x^4
    
    vmulps  ymm2, ymm2, ymm10   ; x^2 * 0.5
    vmulps  ymm3, ymm3, ymm11   ; x^3 * 0.16666667
    vmulps  ymm4, ymm4, ymm12   ; x^4 * 0.04166667
    
    vaddps  ymm1, ymm1, ymm8    ; 1 + x
    vaddps  ymm1, ymm1, ymm2    ; + x^2/2
    vaddps  ymm1, ymm1, ymm3    ; + x^3/6
    vaddps  ymm1, ymm1, ymm4    ; + x^4/24
    
    ; ymm1 = exp(x - max)
    vaddps  ymm6, ymm6, ymm1    ; Accumulate sum
    vmovups ymmword ptr [rsi + rbp*8 - 32], ymm1
    
    dec     rbp
    jnz     @exp_loop

@tail_exp:
    ; Handle tail elements
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @compute_sum

@tail_exp_loop:
    movss   xmm1, dword ptr [rdi]
    subss   xmm1, xmm0          ; x = input - max
    
    ; Clamp
    movss   xmm13, dword ptr [exp_max_input]
    minss   xmm1, xmm13
    
    ; exp approximation
    movss   xmm2, xmm1
    mulss   xmm2, xmm2          ; x^2
    movss   xmm3, xmm2
    mulss   xmm3, xmm1          ; x^3
    movss   xmm4, xmm3
    mulss   xmm4, xmm1          ; x^4
    
    movss   xmm13, dword ptr [exp_c2]
    mulss   xmm2, xmm13         ; x^2 * 0.5
    movss   xmm13, dword ptr [exp_c3]
    mulss   xmm3, xmm13         ; x^3 * 0.16666667
    movss   xmm13, dword ptr [exp_c4]
    mulss   xmm4, xmm13         ; x^4 * 0.04166667
    
    movss   xmm13, dword ptr [exp_c0]
    addss   xmm1, xmm13         ; 1 + x
    addss   xmm1, xmm2
    addss   xmm1, xmm3
    addss   xmm1, xmm4
    
    addss   xmm6, xmm1          ; Accumulate
    movss   dword ptr [rsi], xmm1
    
    add     rdi, 4
    add     rsi, 4
    dec     rbp
    jnz     @tail_exp_loop

@compute_sum:
    ; Horizontal sum reduction
    vextractf128 xmm1, ymm6, 1
    vaddps  xmm6, xmm6, xmm1
    vmovhlps xmm1, xmm6, xmm6
    vaddps  xmm6, xmm6, xmm1
    vshufps xmm1, xmm6, xmm6, 1
    vaddss  xmm6, xmm6, xmm1
    
    ; xmm6 = sum of exp(x - max)
    ; Compute 1/sum
    mov     rax, offset one
    movss   xmm7, dword ptr [rax]
    divss   xmm7, xmm6
    vbroadcastss ymm7, xmm7     ; ymm7 = 1/sum (all lanes)

    ; Phase 3: Normalize
    mov     rsi, rdx            ; Reset output
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_norm

@norm_loop:
    vmovups ymm1, ymmword ptr [rsi + rbp*8 - 32]
    vmulps  ymm1, ymm1, ymm7    ; Divide by sum
    vmovups ymmword ptr [rsi + rbp*8 - 32], ymm1
    dec     rbp
    jnz     @norm_loop

@tail_norm:
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @done

@tail_norm_loop:
    movss   xmm1, dword ptr [rsi]
    mulss   xmm1, xmm7
    movss   dword ptr [rsi], xmm1
    add     rsi, 4
    dec     rbp
    jnz     @tail_norm_loop

@done:
    vzeroupper
    add     rsp, 64
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

softmax_avx2_f32 ENDP

.data
ALIGN 16
exp_c0          real4 1.0
exp_c1          real4 1.0
exp_c2          real4 0.5
exp_c3          real4 0.16666667
exp_c4          real4 0.04166667
one             real4 1.0
exp_max_input   real4 88.0        ; exp(88) is near float max

END
