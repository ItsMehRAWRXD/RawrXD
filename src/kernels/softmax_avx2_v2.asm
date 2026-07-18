; Softmax AVX2 Optimized Implementation v2
; Target: 3.0x+ speedup over scalar reference
; Fixed for MASM x64 syntax

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

    mov     rdi, rcx
    mov     rsi, rdx
    mov     rbx, r8

    vbroadcastss ymm0, dword ptr [rdi]
    
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
    vextractf128 xmm1, ymm0, 1
    vmaxps  xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm0, xmm0
    vmaxps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vmaxss  xmm0, xmm0, xmm1
    
    vbroadcastss ymm5, xmm0
    mov     rdi, rcx
    vxorps  ymm6, ymm6, ymm6
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_exp

@exp_loop:
    vmovups ymm1, ymmword ptr [rdi + rbp*8 - 32]
    vsubps  ymm1, ymm1, ymm5
    
    ; exp approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmulps  ymm2, ymm1, ymm1
    vmulps  ymm3, ymm2, ymm1
    vmulps  ymm4, ymm3, ymm1
    
    vbroadcastss ymm7, dword ptr [exp_c2]
    vbroadcastss ymm8, dword ptr [exp_c3]
    vbroadcastss ymm9, dword ptr [exp_c4]
    
    vmulps  ymm2, ymm2, ymm7
    vmulps  ymm3, ymm3, ymm8
    vmulps  ymm4, ymm4, ymm9
    
    vbroadcastss ymm7, dword ptr [exp_c0]
    vaddps  ymm1, ymm1, ymm7
    vaddps  ymm1, ymm1, ymm2
    vaddps  ymm1, ymm1, ymm3
    vaddps  ymm1, ymm1, ymm4
    
    vaddps  ymm6, ymm6, ymm1
    vmovups ymmword ptr [rsi + rbp*8 - 32], ymm1
    
    dec     rbp
    jnz     @exp_loop

@tail_exp:
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @compute_sum

@tail_exp_loop:
    movss   xmm1, dword ptr [rdi]
    subss   xmm1, xmm0
    
    movss   xmm2, xmm1
    mulss   xmm2, xmm2          ; xmm2 = x^2
    movss   xmm3, xmm2
    mulss   xmm3, xmm1          ; xmm3 = x^3
    movss   xmm4, xmm3
    mulss   xmm4, xmm1          ; xmm4 = x^4
    
    mov     rax, offset exp_c2
    movss   xmm8, dword ptr [rax]
    mov     rax, offset exp_c3
    movss   xmm9, dword ptr [rax]
    mov     rax, offset exp_c4
    movss   xmm10, dword ptr [rax]
    
    mulss   xmm2, xmm8
    mulss   xmm3, xmm9
    mulss   xmm4, xmm10
    
    mov     rax, offset exp_c0
    movss   xmm7, dword ptr [rax]
    addss   xmm1, xmm7
    addss   xmm1, xmm2
    addss   xmm1, xmm3
    addss   xmm1, xmm4
    
    addss   xmm6, xmm1
    movss   dword ptr [rsi], xmm1
    
    add     rdi, 4
    add     rsi, 4
    dec     rbp
    jnz     @tail_exp_loop

@compute_sum:
    vextractf128 xmm1, ymm6, 1
    vaddps  xmm6, xmm6, xmm1
    vmovhlps xmm1, xmm6, xmm6
    vaddps  xmm6, xmm6, xmm1
    vshufps xmm1, xmm6, xmm6, 1
    vaddss  xmm6, xmm6, xmm1
    
    movss   xmm7, dword ptr [one]
    divss   xmm7, xmm6
    vbroadcastss ymm7, xmm7

    mov     rsi, rdx
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_norm

@norm_loop:
    vmovups ymm1, ymmword ptr [rsi + rbp*8 - 32]
    vmulps  ymm1, ymm1, ymm7
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
exp_c0  real4 1.0
exp_c1  real4 1.0
exp_c2  real4 0.5
exp_c3  real4 0.16666667
exp_c4  real4 0.04166667
one     real4 1.0

END
