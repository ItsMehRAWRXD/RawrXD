; RMSNorm AVX2 Optimized Implementation v2
; Target: 2.5x+ speedup over scalar reference
; Fixed for MASM x64 syntax

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

    mov     rdi, rcx
    mov     rsi, rdx
    mov     rbx, r8
    vbroadcastss ymm7, xmm3
    
    vxorps  ymm0, ymm0, ymm0
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_sum

@loop_sum:
    vmovups ymm1, ymmword ptr [rdi]
    vmulps  ymm2, ymm1, ymm1
    vaddps  ymm0, ymm0, ymm2
    add     rdi, 32
    dec     rbp
    jnz     @loop_sum

@tail_sum:
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm0, xmm0
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vaddss  xmm0, xmm0, xmm1
    
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @compute_rms
    
    vxorps  xmm2, xmm2, xmm2
@tail_loop:
    movss   xmm3, dword ptr [rdi]
    mulss   xmm3, xmm3
    addss   xmm2, xmm3
    add     rdi, 4
    dec     rbp
    jnz     @tail_loop
    
    addss   xmm0, xmm2

@compute_rms:
    cvtsi2ss xmm1, ebx
    divss   xmm0, xmm1
    addss   xmm0, xmm7
    sqrtss  xmm0, xmm0
    movss   xmm6, dword ptr [one]
    divss   xmm6, xmm0
    vbroadcastss ymm6, xmm6
    
    mov     rdi, rcx
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_normalize

@loop_normalize:
    vmovups ymm1, ymmword ptr [rdi]
    vmulps  ymm1, ymm1, ymm6
    vmovups ymmword ptr [rsi], ymm1
    add     rdi, 32
    add     rsi, 32
    dec     rbp
    jnz     @loop_normalize

@tail_normalize:
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @done
    
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
