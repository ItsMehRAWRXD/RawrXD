; ============================================================================
; deep2_kernel.asm - Deep2 Engine MASM x64 Implementation
; High-performance vector kernels for MoE inference
; 
; Compile: ml64 /c /nologo /Fo deep2_kernel.obj deep2_kernel.asm
; ============================================================================

.code

; ============================================================================
; Deep2_VecDotProduct - Vector dot product with AVX2
; void Deep2_VecDotProduct(float* a, float* b, float* out, size_t n);
; RCX = a, RDX = b, R8 = out, R9 = n
; ============================================================================
Deep2_VecDotProduct PROC
    vxorps ymm0, ymm0, ymm0     ; Zero out accumulation register
    test r9, r9                 ; Check if n == 0
    jz done

loop_start:
    vmovups ymm1, [rcx]         ; Load 8 floats from a
    vmovups ymm2, [rdx]         ; Load 8 floats from b
    vfmadd231ps ymm0, ymm1, ymm2 ; Fused Multiply-Add: ymm0 += ymm1 * ymm2
    
    add rcx, 32                 ; Advance pointer by 8 floats (32 bytes)
    add rdx, 32
    sub r9, 8
    ja loop_start

    ; Horizontal add of ymm0 to get final scalar
    vextractf128 xmm1, ymm0, 1  ; Extract high 128 bits (lane 1)
    vaddps xmm0, xmm0, xmm1     ; Add high and low
    vhaddps xmm0, xmm0, xmm0    ; Horizontal add
    vhaddps xmm0, xmm0, xmm0    ; Final horizontal add
    
    movss dword ptr [r8], xmm0  ; Store result

done:
    vzeroupper                  ; Clear upper YMM state
    ret
Deep2_VecDotProduct ENDP

; ============================================================================
; Deep2_SwiGLU - Swish-Gated Linear Unit activation
; void Deep2_SwiGLU(float* x, float* y, float* out, size_t n);
; RCX = x, RDX = y, R8 = out, R9 = n
; Computes: out = (x * sigmoid(x)) * y
; ============================================================================
Deep2_SwiGLU PROC
    test r9, r9
    jz done_swiglu

    ; Load constants
    vmovups ymm10, ymmword ptr const_log2e
    vmovups ymm11, ymmword ptr const_one
    vmovups ymm12, ymmword ptr const_0_5
    vmovups ymm13, ymmword ptr const_0_1666
    vmovups ymm14, ymmword ptr const_sign_mask

loop_swiglu:
    vmovups ymm0, [rcx]         ; Load x
    vmovups ymm1, [rdx]         ; Load y
    
    ; Calculate sigmoid(x) = 1 / (1 + exp(-x))
    ; First compute exp(-x)
    vxorps ymm2, ymm0, ymm14    ; ymm2 = -x (flip sign bit)
    
    ; Fast exp approximation via 2^(x * log2e)
    vmulps ymm2, ymm2, ymm10    ; ymm2 = -x * log2(e)
    vroundps ymm3, ymm2, 1      ; ymm3 = floor(ymm2)
    vsubps ymm2, ymm2, ymm3     ; ymm2 = fractional part
    
    ; Polynomial approximation: 2^f ≈ 1 + f*(1 + f*(0.5 + f*0.1666))
    vmovaps ymm4, ymm13         ; ymm4 = 0.1666
    vfmadd213ps ymm4, ymm2, ymm12 ; ymm4 = 0.5 + f*0.1666
    vfmadd213ps ymm4, ymm2, ymm11 ; ymm4 = 1 + f*(0.5 + f*0.1666)
    vfmadd213ps ymm4, ymm2, ymm11 ; ymm4 = 1 + f*(1 + f*(0.5 + f*0.1666))
    vmulps ymm4, ymm4, ymm2     ; ymm4 *= f
    vaddps ymm4, ymm4, ymm11    ; ymm4 += 1
    
    ; Add exponent: (int)floor << 23
    vcvtps2dq ymm3, ymm3
    vpslld ymm3, ymm3, 23
    vpaddd ymm4, ymm4, ymm3     ; ymm4 = exp(-x)
    
    ; Sigmoid: 1 / (1 + exp(-x))
    vaddps ymm4, ymm4, ymm11    ; ymm4 = 1 + exp(-x)
    vrcpps ymm4, ymm4          ; ymm4 ≈ 1 / (1 + exp(-x))
    
    ; SwiGLU: (x * sigmoid(x)) * y
    vmulps ymm0, ymm0, ymm4    ; ymm0 = x * sigmoid(x) = SiLU(x)
    vmulps ymm0, ymm0, ymm1    ; ymm0 = SiLU(x) * y
    
    vmovups [r8], ymm0          ; Store result
    
    add rcx, 32
    add rdx, 32
    add r8, 32
    sub r9, 8
    ja loop_swiglu

done_swiglu:
    vzeroupper
    ret
Deep2_SwiGLU ENDP

; ============================================================================
; Deep2_RMSNorm - Root Mean Square Normalization
; void Deep2_RMSNorm(float* x, float* out, size_t n, float eps);
; RCX = x, RDX = out, R8 = n, XMM3 = eps
; ============================================================================
Deep2_RMSNorm PROC
    test r8, r8
    jz done_rms
    
    vxorps ymm0, ymm0, ymm0     ; Accumulator for sum of squares
    mov r9, r8                  ; Save n for second pass
    push rcx                    ; Save x pointer
    
    ; First pass: compute sum of squares
sum_loop:
    vmovups ymm1, [rcx]
    vmulps ymm1, ymm1, ymm1     ; ymm1 = x * x
    vaddps ymm0, ymm0, ymm1     ; accumulate
    add rcx, 32
    sub r8, 8
    ja sum_loop
    
    ; Horizontal sum of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Compute rms = sqrt(sum / n + eps)
    vcvtsi2ss xmm2, xmm2, r9d   ; xmm2 = n (as float)
    vdivss xmm0, xmm0, xmm2     ; xmm0 = sum / n
    vaddss xmm0, xmm0, xmm3     ; xmm0 = mean + eps
    vsqrtss xmm0, xmm0, xmm0    ; xmm0 = rms
    vrcpss xmm0, xmm0, xmm0     ; xmm0 = 1/rms (scale factor)
    vbroadcastss ymm0, xmm0     ; Broadcast to all lanes
    
    ; Second pass: normalize
    pop rcx                     ; Restore x pointer
    mov r8, r9                  ; Restore n
    
norm_loop:
    vmovups ymm1, [rcx]
    vmulps ymm1, ymm1, ymm0     ; x * scale
    vmovups [rdx], ymm1
    add rcx, 32
    add rdx, 32
    sub r8, 8
    ja norm_loop

done_rms:
    vzeroupper
    ret
Deep2_RMSNorm ENDP

; ============================================================================
; Data Segment - Constants
; ============================================================================
.const
align 16
const_log2e     real4 1.44269504, 1.44269504, 1.44269504, 1.44269504, 1.44269504, 1.44269504, 1.44269504, 1.44269504
const_one       real4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
const_0_5       real4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5
const_0_1666    real4 0.16666666, 0.16666666, 0.16666666, 0.16666666, 0.16666666, 0.16666666, 0.16666666, 0.16666666
const_sign_mask dd 80000000h, 80000000h, 80000000h, 80000000h, 80000000h, 80000000h, 80000000h, 80000000h

END
