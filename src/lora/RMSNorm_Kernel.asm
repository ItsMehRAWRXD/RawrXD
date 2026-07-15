; ==============================================================================
; RMSNorm_Kernel.asm - High-Performance Vector Normalization
; Signature: void RMSNorm_Kernel(float* x, float* weight, float* out, float epsilon, size_t dim);
; Windows x64 ABI Layout:
;   RCX = x (source pointer)
;   RDX = weight (gamma scale pointer)
;   R8  = out (destination pointer)
;   XMM3 = epsilon (scalar float)
;   [rbp+48] = dim (size_t vector length, block-aligned to 8)
; ==============================================================================

.code

RMSNorm_Kernel PROC FRAME
    ; 1. Setup Shadow Space & Frame Pointer
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; 2. Correctly extract the 5th parameter from shadow space boundary
    mov     r10, [rbp + 48]        ; r10 = dim (Extracted from true caller frame)
    
    ; Debug: check if parameters are valid
    test    r10, r10
    jz      ExitEarly
    
    ; 3. Pre-convert dimension to float while registers are clean
    vxorps  xmm4, xmm4, xmm4       ; Clear xmm4
    vcvtsi2ss xmm4, xmm4, r10      ; xmm4 = float(dim)
    
    ; 4. Preserve epsilon in xmm3 for scalar operations
    ; xmm3 already contains epsilon (4th parameter)

    ; 3. Stage Vector Accumulators
    vxorps  ymm0, ymm0, ymm0       ; ymm0 = clear for sum of squares accumulation
    xor     rax, rax               ; rax = loop index counter

SumLoopAVX:
    vmovups ymm1, [rcx + rax*4]    ; Load 8 floats from x
    vmulps  ymm1, ymm1, ymm1       ; ymm1 = x_i * x_i
    vaddps  ymm0, ymm0, ymm1       ; ymm0 += x_i^2
    add     rax, 8
    cmp     rax, r10
    jl      SumLoopAVX

    ; 4. Horizontal Reduction (Summing all 8 floating-point lanes in YMM0)
    vextractf128 xmm2, ymm0, 1     ; xmm2 = high 128-bits of ymm0
    vaddps  xmm0, xmm0, xmm2       ; xmm0 = [f0+f4, f1+f5, f2+f6, f3+f7]
    vmovshdup xmm2, xmm0           ; xmm2 = duplicate odd elements
    vaddps  xmm0, xmm0, xmm2       ; xmm0 = horizontal adjacent pairs summed
    vpermilps xmm2, xmm0, 04Eh     ; Permute lanes (0x4E = 01 00 11 10) to align remaining halves
    vaddps  xmm0, xmm0, xmm2       ; xmm0[0] now contains the grand sum of squares

    ; 5. Calculate RMS Scale Factor: 1.0 / sqrt((sum / dim) + epsilon)
    vdivss  xmm0, xmm0, xmm4       ; xmm0 = sum / dim (using pre-converted dim)
    vaddss  xmm0, xmm0, xmm3       ; xmm0 = (sum / dim) + epsilon
    vsqrtss xmm0, xmm0, xmm0       ; xmm0 = sqrt((sum / dim) + epsilon)
    
    mov     eax, 3F800000h         ; Floating-point hexadecimal bitmask representation of 1.0f
    vmovd   xmm2, eax              ; Stash 1.0f into xmm2
    vdivss  xmm0, xmm2, xmm0       ; xmm0 = 1.0f / rms (Scalar reciprocal scaling factor)

    vpbroadcastd ymm0, xmm0        ; Broadcast scalar scale factor across all 8 lanes of YMM0

    ; 6. Normalization Projection Loop
    xor     rax, rax               ; Reset loop counter

NormalizeLoopAVX:
    vmovups ymm1, [rcx + rax*4]    ; ymm1 = original x elements
    vmovups ymm2, [rdx + rax*4]    ; ymm2 = weight scaling elements
    vmulps  ymm1, ymm1, ymm0       ; ymm1 = x * scale_factor
    vmulps  ymm1, ymm1, ymm2       ; ymm1 = (x * scale_factor) * weight
    vmovups [r8 + rax*4], ymm1     ; Write back 8 fully normalized floats to destination
    add     rax, 8
    cmp     rax, r10
    jl      NormalizeLoopAVX

    ; 7. Safe Demobilization
    vzeroupper                     ; Cleanse context state to prevent AVX-SSE execution penalties
    
ExitEarly:
    mov     rsp, rbp
    pop     rbp
    ret
RMSNorm_Kernel ENDP

END