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
; n must be a multiple of 8; caller is responsible for padding.
; ============================================================================
Deep2_VecDotProduct PROC
    test r9, r9
    jz done

    vxorps ymm0, ymm0, ymm0     ; Zero accumulator

loop_start:
    vmovaps ymm1, [rcx]         ; Aligned load 8 floats from a
    vfmadd231ps ymm0, ymm1, [rdx] ; ymm0 += a * b  (aligned load of b)
    
    add rcx, 32
    add rdx, 32
    sub r9, 8
    ja loop_start

    ; Horizontal reduction of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    vmovss dword ptr [r8], xmm0

done:
    vzeroupper
    ret
Deep2_VecDotProduct ENDP

; ============================================================================
; Deep2_SwiGLU - Swish-Gated Linear Unit activation
; void Deep2_SwiGLU(float* x, float* y, float* out, size_t n);
; RCX = x, RDX = y, R8 = out, R9 = n
; Computes: out[i] = (x[i] * sigmoid(x[i])) * y[i]   (SiLU(x) * y)
; n must be a multiple of 8.
; ============================================================================
Deep2_SwiGLU PROC
    test r9, r9
    jz done_swiglu

    ; Broadcast constants
    vbroadcastss ymm10, dword ptr [const_log2e]
    vbroadcastss ymm11, dword ptr [const_one]
    vbroadcastss ymm12, dword ptr [const_0_5]
    vbroadcastss ymm13, dword ptr [const_0_1666]
    vbroadcastss ymm14, dword ptr [const_sign_mask_f]

loop_swiglu:
    vmovaps ymm0, [rcx]         ; x  (aligned)
    vmovaps ymm1, [rdx]         ; y  (aligned)

    ; --- compute sigmoid(x) = 1 / (1 + exp(-x)) ---
    ; negate x
    vxorps  ymm2, ymm0, ymm14   ; ymm2 = -x

    ; fast exp(-x) via 2^(-x * log2e)
    vmulps  ymm2, ymm2, ymm10   ; ymm2 = -x * log2(e)
    vroundps ymm3, ymm2, 1      ; ymm3 = floor(ymm2)  (round toward -inf)
    vsubps  ymm2, ymm2, ymm3    ; ymm2 = fractional part f in [0,1)

    ; Horner: 2^f ≈ 1 + f*(1 + f*(0.5 + f*0.16667))
    ; ymm4 = 0.16667
    vmovaps ymm4, ymm13
    ; ymm4 = 0.5 + f*0.16667
    vfmadd213ps ymm4, ymm2, ymm12
    ; ymm4 = 1 + f*(0.5 + f*0.16667)
    vfmadd213ps ymm4, ymm2, ymm11
    ; ymm4 = 1 + f*(1 + f*(0.5 + f*0.16667))  -- correct Horner step
    vfmadd132ps ymm4, ymm11, ymm2

    ; Reconstruct 2^floor via integer exponent trick
    vcvtps2dq ymm3, ymm3        ; floor as int32
    vpslld    ymm3, ymm3, 23    ; shift into IEEE754 exponent field
    vpaddd    ymm4, ymm4, ymm3  ; ymm4 = exp(-x)  (float reinterpret)

    ; sigmoid = 1 / (1 + exp(-x))  -- use Newton-Raphson refinement
    vaddps  ymm4, ymm4, ymm11   ; ymm4 = 1 + exp(-x)
    vrcpps  ymm5, ymm4          ; ymm5 ≈ 1/ymm4  (12-bit approx)
    ; NR step: r = r*(2 - d*r)
    vmulps  ymm6, ymm4, ymm5    ; d*r
    vsubps  ymm6, ymm11, ymm6   ; 1 - d*r  (use ymm11=1.0 as 2-d*r base)
    vaddps  ymm6, ymm11, ymm6   ; 2 - d*r
    vmulps  ymm5, ymm5, ymm6    ; refined sigmoid

    ; SiLU(x) = x * sigmoid(x)
    vmulps  ymm0, ymm0, ymm5
    ; SwiGLU = SiLU(x) * y
    vmulps  ymm0, ymm0, ymm1

    vmovaps [r8], ymm0

    add rcx, 32
    add rdx, 32
    add r8,  32
    sub r9,  8
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
; Data Segment - Constants (scalar, broadcast at runtime)
; ============================================================================
.const
align 4
const_log2e      real4 1.44269504
const_one        real4 1.0
const_0_5        real4 0.5
const_0_1666     real4 0.16666667
const_sign_mask_f dd 80000000h

END
