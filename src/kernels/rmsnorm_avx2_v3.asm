; RMSNorm AVX2 Optimized Implementation v3
; Fixed numerical precision with Newton-Raphson refinement
; Target: >3x speedup, <1e-5 max error
;
; Formula: y = x / sqrt(mean(x^2) + epsilon)
; Using rsqrt + Newton-Raphson for accuracy

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
    vfmadd231ps ymm0, ymm1, ymm1    ; Fused multiply-add: acc += x * x
    add     rdi, 32
    dec     rbp
    jnz     @loop_sum

@tail_sum:
    ; Horizontal sum of ymm0
    ; Extract high 128 bits and add to low
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    
    ; Sum the 4 floats in xmm0
    vmovhlps xmm1, xmm0, xmm0     ; Move high 2 to low
    vaddps  xmm0, xmm0, xmm1      ; Add pairs
    vshufps xmm1, xmm0, xmm0, 1   ; Get element 1
    vaddss  xmm0, xmm0, xmm1      ; Final sum in xmm0[0]
    
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
    cvtsi2ss xmm1, ebx            ; xmm1 = float(n)
    divss   xmm0, xmm1            ; xmm0 = mean
    
    ; mean + epsilon
    addss   xmm0, xmm7            ; xmm0 = mean + epsilon
    
    ; Compute rsqrt with Newton-Raphson refinement
    ; rsqrt(x) approximation
    rsqrtss xmm1, xmm0            ; xmm1 = approx_rsqrt
    
    ; Newton-Raphson iteration: y = y * (1.5 - 0.5 * x * y * y)
    ; xmm2 = 0.5 * x * y * y
    movss   xmm2, xmm1
    mulss   xmm2, xmm2            ; xmm2 = y * y
    mulss   xmm2, xmm0            ; xmm2 = x * y * y
    mov     rax, offset half
    mulss   xmm2, dword ptr [rax]; xmm2 = 0.5 * x * y * y
    
    ; xmm3 = 1.5 - xmm2
    mov     rax, offset one_point_five
    movss   xmm3, dword ptr [rax]; xmm3 = 1.5
    subss   xmm3, xmm2            ; xmm3 = 1.5 - 0.5*x*y*y
    
    ; xmm1 = y * xmm3 (refined rsqrt)
    mulss   xmm1, xmm3
    
    ; xmm1 = inv_rms (refined)
    vbroadcastss ymm6, xmm1       ; ymm6 = inv_rms (all lanes)
    
    ; Phase 2: Normalize
    mov     rdi, rcx              ; Reset input pointer
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_normalize

    ; Main normalization loop
@loop_normalize:
    vmovups ymm1, ymmword ptr [rdi]
    vmulps  ymm1, ymm1, ymm6      ; x * inv_rms
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
    
    ; Extract scalar inv_rms
    movss   xmm6, xmm6
    
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
half            real4 0.5
one_point_five  real4 1.5

END
