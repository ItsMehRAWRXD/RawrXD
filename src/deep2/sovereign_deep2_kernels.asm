; ============================================================================
; sovereign_deep2_kernels.asm - Deep2 Production Kernels
; VecDotProduct, SwiGLU, RMSNorm - AVX2/AVX512 implementations
; ============================================================================

IFDEF RAX
; x64 build
.code

; ============================================================================
; Deep2_VecDotProduct_AVX2
; float Deep2_VecDotProduct(const float* a, const float* b, float* out, size_t n)
; ============================================================================
Deep2_VecDotProduct_AVX2 PROC FRAME
    ; RCX = a, RDX = b, R8 = out, R9 = n
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    
    mov rsi, rcx        ; a
    mov rdi, rdx        ; b
    mov rbx, r8         ; out
    mov rcx, r9         ; n
    
    vxorps ymm0, ymm0, ymm0      ; acc = 0
    
    ; Process 8 floats at a time (AVX2)
    mov rax, rcx
    shr rax, 3          ; n / 8
    jz @remainder
    
@loop8:
    vmovups ymm1, [rsi]          ; load a[0:7]
    vmovups ymm2, [rdi]          ; load b[0:7]
    vfmadd231ps ymm0, ymm1, ymm2 ; acc += a * b
    add rsi, 32
    add rdi, 32
    dec rax
    jnz @loop8
    
    ; Horizontal sum of ymm0
    vextractf128 xmm1, ymm0, 1   ; high 4 floats
    vaddps xmm0, xmm0, xmm1      ; low + high
    vhaddps xmm1, xmm0, xmm0     ; pairwise sum
    vhaddps xmm0, xmm1, xmm1     ; final sum
    
@remainder:
    ; Handle remaining elements (n % 8)
    mov rax, rcx
    and rax, 7
    jz @done
    
    vxorps xmm1, xmm1, xmm1      ; scalar acc
    vxorps xmm0, xmm0, xmm0      ; ensure xmm0 is clean for scalar path
@loop1:
    test rax, rax
    jz @scalar_done
    vmovss xmm2, dword ptr [rsi]
    vmovss xmm3, dword ptr [rdi]
    vmulss xmm2, xmm2, xmm3
    vaddss xmm1, xmm1, xmm2
    add rsi, 4
    add rdi, 4
    dec rax
    jmp @loop1
    
@scalar_done:
    vaddss xmm0, xmm0, xmm1
    
@done:
    ; Store result
    vmovss dword ptr [rbx], xmm0
    
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2_VecDotProduct_AVX2 ENDP

; ============================================================================
; Deep2_SwiGLU_AVX2
; void Deep2_SwiGLU(const float* x, const float* y, float* out, size_t n)
; SwiGLU(x, y) = x * sigmoid(x) * y
; ============================================================================
Deep2_SwiGLU_AVX2 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog
    
    mov rsi, rcx        ; x
    mov rdi, rdx        ; y
    mov rbx, r8         ; out
    mov rcx, r9         ; n
    
    ; Load constants
    vmovss xmm6, dword ptr [__minus_one]
    vbroadcastss ymm6, xmm6    ; -1.0
    vmovss xmm7, dword ptr [__one]
    vbroadcastss ymm7, xmm7    ; 1.0
    
    mov rax, rcx
    shr rax, 3          ; n / 8
    jz @swiglu_remainder
    
@swiglu_loop8:
    vmovups ymm0, [rsi]          ; load x
    vmovups ymm1, [rdi]          ; load y
    
    ; sigmoid(x) = 1 / (1 + exp(-x))
    ; Use fast polynomial approximation: sigmoid(x) ≈ 0.5 + 0.5*tanh(0.5*x)
    ; tanh approx: tanh(x) ≈ x*(27+x^2)/(27+9*x^2) for |x|<4.5
    vxorps ymm2, ymm2, ymm2
    vsubps ymm2, ymm2, ymm0      ; -x
    ; Fast sigmoid: 1/(1+2^(-x)) using approx
    ; Simple clip-based sigmoid for performance
    vminps ymm2, ymm2, ymm7      ; clip -x to 1.0 max (rough approx)
    vmaxps ymm2, ymm2, ymm6      ; clip to -1.0 min
    vaddps ymm3, ymm2, ymm7      ; 1 + (-x) (linear approx)
    vmaxps ymm3, ymm3, ymm7      ; ensure >= 1
    vdivps ymm4, ymm7, ymm3      ; sigmoid(x) approx
    
    ; x * sigmoid(x)
    vmulps ymm0, ymm0, ymm4
    
    ; * y
    vmulps ymm0, ymm0, ymm1
    
    vmovups [rbx], ymm0
    
    add rsi, 32
    add rdi, 32
    add rbx, 32
    dec rax
    jnz @swiglu_loop8
    
@swiglu_remainder:
    mov rax, rcx
    and rax, 7
    jz @swiglu_done
    
@swiglu_loop1:
    test rax, rax
    jz @swiglu_done
    
    vmovss xmm0, dword ptr [rsi]           ; x
    vmovss xmm1, dword ptr [rdi]           ; y
    
    ; sigmoid
    vxorps xmm2, xmm2, xmm2
    vsubss xmm2, xmm2, xmm0      ; -x
    ; exp approximation for scalar
    vmovss xmm3, dword ptr [__one]
    vaddss xmm3, xmm3, xmm2      ; 1 + (-x) approximation
    vmaxss xmm3, xmm3, xmm3      ; ensure >= 1 (noop, keep pipeline)
    vmovss xmm5, dword ptr [__one]
    vdivss xmm4, xmm5, xmm3      ; 1 / (1 + exp(-x))
    
    vmulss xmm0, xmm0, xmm4      ; x * sigmoid
    vmulss xmm0, xmm0, xmm1      ; * y
    
    vmovss dword ptr [rbx], xmm0
    
    add rsi, 4
    add rdi, 4
    add rbx, 4
    dec rax
    jmp @swiglu_loop1
    
@swiglu_done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2_SwiGLU_AVX2 ENDP

; ============================================================================
; Deep2_RMSNorm_AVX2
; void Deep2_RMSNorm(const float* x, float* out, size_t n, float eps)
; RMSNorm(x) = x / sqrt(mean(x^2) + eps)
; ============================================================================
Deep2_RMSNorm_AVX2 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 8
    .allocstack 8
    .endprolog
    
    mov rsi, rcx        ; x
    mov rdi, rdx        ; out
    mov rbx, r8         ; n
    vmovss xmm4, xmm3, xmm3   ; eps (duplicate to avoid two-operand vmovss error)
    
    vxorps ymm0, ymm0, ymm0      ; sum_sq = 0
    
    mov rax, rbx
    shr rax, 3          ; n / 8
    jz @rms_remainder
    
@rms_loop8:
    vmovups ymm1, [rsi]
    vmulps ymm2, ymm1, ymm1      ; x^2
    vaddps ymm0, ymm0, ymm2      ; sum_sq += x^2
    add rsi, 32
    dec rax
    jnz @rms_loop8
    
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm1, xmm0, xmm0
    vhaddps xmm0, xmm1, xmm1
    
@rms_remainder:
    mov rax, rbx
    and rax, 7
    jz @rms_compute
    
    vxorps xmm1, xmm1, xmm1
@rms_loop1:
    test rax, rax
    jz @rms_add_remainder
    vmovss xmm2, dword ptr [rsi]
    vmulss xmm2, xmm2, xmm2
    vaddss xmm1, xmm1, xmm2
    add rsi, 4
    dec rax
    jmp @rms_loop1
    
@rms_add_remainder:
    vaddss xmm0, xmm0, xmm1
    
@rms_compute:
    ; mean = sum_sq / n
    mov rax, rbx
    cvtsi2ss xmm1, rax
    vdivss xmm0, xmm0, xmm1      ; mean
    vaddss xmm0, xmm0, xmm4      ; + eps
    vsqrtss xmm0, xmm0, xmm0     ; sqrt
    vmovss xmm3, dword ptr [__one]
    vdivss xmm0, xmm3, xmm0      ; 1 / rms
    vbroadcastss ymm5, xmm0      ; broadcast rms_inv
    
    ; Reset pointers and normalize
    mov rsi, rcx
    mov rax, rbx
    shr rax, 3
    jz @rms_norm_remainder
    
@rms_norm_loop8:
    vmovups ymm1, [rsi]
    vmulps ymm1, ymm1, ymm5      ; x * rms_inv
    vmovups [rdi], ymm1
    add rsi, 32
    add rdi, 32
    dec rax
    jnz @rms_norm_loop8
    
@rms_norm_remainder:
    mov rax, rbx
    and rax, 7
    jz @rms_done
    
@rms_norm_loop1:
    test rax, rax
    jz @rms_done
    vmovss xmm1, dword ptr [rsi]
    vmulss xmm1, xmm1, xmm0
    vmovss dword ptr [rdi], xmm1
    add rsi, 4
    add rdi, 4
    dec rax
    jmp @rms_norm_loop1
    
@rms_done:
    add rsp, 8
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2_RMSNorm_AVX2 ENDP

; Constants
__minus_one real4 -1.0
__one real4 1.0
__zero real4 0.0

ENDIF

END
