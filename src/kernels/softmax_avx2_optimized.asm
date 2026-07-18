; Softmax AVX2 Optimized Implementation
; Target: 3.0x+ speedup over scalar reference
; Author: RawrXD Optimization Team
; Date: 2026-07-17

; Softmax: exp(x - max) / sum(exp(x - max))
; Optimizations:
;   - Single-pass max finding + online sum
;   - Fused max-reduction with SIMD
;   - Polynomial exp approximation
;   - Vectorized normalization

.code

; extern "C" void softmax_avx2_f32(
;     const float* input,      ; rcx
;     float* output,           ; rdx
;     size_t n                 ; r8
; );

softmax_avx2_f32 PROC FRAME
    ; Save non-volatile registers
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

    ; Arguments:
    ; rcx = input pointer
    ; rdx = output pointer
    ; r8  = n (number of elements)

    mov     rdi, rcx        ; rdi = input
    mov     rsi, rdx        ; rsi = output
    mov     rbx, r8         ; rbx = n

    ; Phase 1: Find max value
    ; Initialize max with first element
    vbroadcastss ymm0, dword ptr [rdi]  ; ymm0 = max (all lanes)
    
    mov     rbp, rbx
    shr     rbp, 3          ; rbp = n / 8
    test    rbp, rbp
    jz      @tail_max

    ; Main max-finding loop
    ALIGN 16
@max_loop:
    vmovups ymm1, [rdi + rbp*8 - 32]    ; Load 8 floats
    vmaxps  ymm0, ymm0, ymm1            ; Update max
    dec     rbp
    jnz     @max_loop

@tail_max:
    ; Horizontal max reduction
    vextractf128 xmm1, ymm0, 1
    vmaxps  xmm0, xmm0, xmm1
    vmovshdup xmm1, xmm0
    vmaxps  xmm0, xmm0, xmm1
    vpermilps xmm1, xmm0, 1
    vmaxps  xmm0, xmm0, xmm1
    
    ; xmm0 = max value
    vbroadcastss ymm5, xmm0             ; ymm5 = max (all lanes)

    ; Phase 2: Compute exp(x - max) and sum
    ; Reset input pointer
    mov     rdi, rcx
    
    vxorps  ymm6, ymm6, ymm6            ; ymm6 = sum accumulator
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_exp

    ; Constants for exp approximation
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vbroadcastss ymm7, dword ptr [exp_c0]  ; 1.0
    vbroadcastss ymm8, dword ptr [exp_c1]  ; 1.0
    vbroadcastss ymm9, dword ptr [exp_c2]  ; 0.5
    vbroadcastss ymm10, dword ptr [exp_c3] ; 0.16666667
    vbroadcastss ymm11, dword ptr [exp_c4] ; 0.04166667

    ALIGN 16
@exp_loop:
    vmovups ymm1, [rdi + rbp*8 - 32]    ; Load input
    vsubps  ymm1, ymm1, ymm5            ; x = input - max
    
    ; Polynomial approximation: exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmulps  ymm2, ymm1, ymm1            ; x^2
    vmulps  ymm3, ymm2, ymm1            ; x^3
    vmulps  ymm4, ymm3, ymm1            ; x^4
    
    vmulps  ymm2, ymm2, ymm9            ; x^2 * 0.5
    vmulps  ymm3, ymm3, ymm10           ; x^3 * 0.16666667
    vmulps  ymm4, ymm4, ymm11           ; x^4 * 0.04166667
    
    vaddps  ymm1, ymm1, ymm7            ; 1 + x
    vaddps  ymm1, ymm1, ymm2            ; + x^2/2
    vaddps  ymm1, ymm1, ymm3            ; + x^3/6
    vaddps  ymm1, ymm1, ymm4            ; + x^4/24
    
    ; ymm1 = exp(x - max)
    vaddps  ymm6, ymm6, ymm1            ; Accumulate sum
    
    ; Store intermediate result
    vmovups [rsi + rbp*8 - 32], ymm1
    
    dec     rbp
    jnz     @exp_loop

@tail_exp:
    ; Handle tail elements
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @compute_sum
    
    ; Process remaining elements (scalar)
    movss   xmm7, dword ptr [exp_c0]    ; 1.0
    movss   xmm8, dword ptr [exp_c1]    ; 1.0
    movss   xmm9, dword ptr [exp_c2]    ; 0.5
    movss   xmm10, dword ptr [exp_c3]   ; 0.16666667
    movss   xmm11, dword ptr [exp_c4]   ; 0.04166667

@tail_exp_loop:
    movss   xmm1, [rdi]
    subss   xmm1, xmm0                    ; x = input - max
    
    ; exp(x) approximation
    mulss   xmm2, xmm1, xmm1              ; x^2
    mulss   xmm3, xmm2, xmm1              ; x^3
    mulss   xmm4, xmm3, xmm1              ; x^4
    
    mulss   xmm2, xmm2, xmm9              ; x^2 * 0.5
    mulss   xmm3, xmm3, xmm10             ; x^3 * 0.16666667
    mulss   xmm4, xmm4, xmm11             ; x^4 * 0.04166667
    
    addss   xmm1, xmm7                    ; 1 + x
    addss   xmm1, xmm2                    ; + x^2/2
    addss   xmm1, xmm3                    ; + x^3/6
    addss   xmm1, xmm4                    ; + x^4/24
    
    addss   xmm6, xmm1                    ; Accumulate sum
    movss   [rsi], xmm1                   ; Store
    
    add     rdi, 4
    add     rsi, 4
    dec     rbp
    jnz     @tail_exp_loop

@compute_sum:
    ; Horizontal sum reduction
    vextractf128 xmm1, ymm6, 1
    vaddps  xmm6, xmm6, xmm1
    vhaddps xmm6, xmm6, xmm6
    vhaddps xmm6, xmm6, xmm6
    
    ; xmm6 = sum of exp(x - max)
    ; Compute 1/sum for division
    movss   xmm7, dword ptr [one]
    divss   xmm7, xmm6                    ; xmm7 = 1/sum
    vbroadcastss ymm7, xmm7               ; ymm7 = 1/sum (all lanes)

    ; Phase 3: Normalize
    mov     rsi, rdx                      ; Reset output pointer
    
    mov     rbp, rbx
    shr     rbp, 3
    test    rbp, rbp
    jz      @tail_norm

    ALIGN 16
@norm_loop:
    vmovups ymm1, [rsi + rbp*8 - 32]    ; Load exp values
    vmulps  ymm1, ymm1, ymm7            ; Divide by sum
    vmovups [rsi + rbp*8 - 32], ymm1    ; Store normalized
    dec     rbp
    jnz     @norm_loop

@tail_norm:
    ; Handle tail normalization
    mov     rbp, rbx
    and     rbp, 7
    test    rbp, rbp
    jz      @done

@tail_norm_loop:
    movss   xmm1, [rsi]
    mulss   xmm1, xmm7                    ; Divide by sum
    movss   [rsi], xmm1
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

; Data section for constants
.data
ALIGN 16
exp_c0  dd 1.0
exp_c1  dd 1.0
exp_c2  dd 0.5
exp_c3  dd 0.16666667
exp_c4  dd 0.04166667
one     dd 1.0

END
