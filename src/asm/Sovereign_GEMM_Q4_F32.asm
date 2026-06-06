; ==============================================================================
; Sovereign_GEMM_Q4_F32.asm - Native Q4_0 Inference Kernel
; Parity: PyTorch Q4_0 Linear Operator (torch.ops.quantized.linear)
; Architecture: x64 AVX-512F / AVX-512BW
;
; Formula: x = (w - 8) * scale
; Block: 32 elements (16 bytes weights + 2 bytes scale = 18 bytes total)
; Elements 0..15 = low nibbles, 16..31 = high nibbles
; ==============================================================================

include Sovereign_Common.inc

.DATA
    ALIGN 16
    mask_b  DD 16 DUP (0000000Fh)        ; dword mask for low-nibble isolation
    bias_8  DD 16 DUP (8)

.CODE

; ------------------------------------------------------------------------------
; Sovereign_GEMM_Q4_F32
; RCX = pWeights (Q4_0 Block: 2 bytes scale + 16 bytes weights)
; RDX = pInput   (F32*)
; R8  = pOutput  (F32*)
; R9  = nElementCount (Must be multiple of 32)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_GEMM_Q4_F32
Sovereign_GEMM_Q4_F32 PROC
    ; Use only volatile SIMD registers (XMM0-5) to satisfy Win64 ABI.
    ; XMM6-XMM15 are nonvolatile and must be preserved by callees.
    vpxord zmm0, zmm0, zmm0     ; ZMM0 = Accumulator (low nibbles)
    vpxord zmm1, zmm1, zmm1     ; ZMM1 = Accumulator (high nibbles)

@@loop:
    ; 1. Load scale (F16) and broadcast
    vpbroadcastw ymm2, word ptr [rcx]
    vcvtph2ps zmm2, ymm2        ; ZMM2 = 16 lanes of scale

    ; 2. Low nibbles (elements 0..15)
    vmovdqu xmm3, xmmword ptr [rcx + 2]
    vpmovzxbd zmm3, xmm3        ; bytes -> dwords
    vmovups zmm4, zmmword ptr [mask_b]
    vmovups zmm5, zmmword ptr [bias_8]
    vpandd zmm3, zmm3, zmm4     ; isolate low nibble
    vpsubd zmm3, zmm3, zmm5     ; (w - 8)
    vcvtdq2ps zmm3, zmm3
    vmulps zmm3, zmm3, zmm2
    vfmadd231ps zmm0, zmm3, zmmword ptr [rdx]

    ; 3. High nibbles (elements 16..31)
    vmovdqu xmm3, xmmword ptr [rcx + 2]
    vpmovzxbd zmm3, xmm3
    vpsrld zmm3, zmm3, 4
    vpandd zmm3, zmm3, zmm4
    vpsubd zmm3, zmm3, zmm5
    vcvtdq2ps zmm3, zmm3
    vmulps zmm3, zmm3, zmm2
    vfmadd231ps zmm1, zmm3, zmmword ptr [rdx + 64]
    
    add rcx, 18                ; sizeof(block_q4_0)
    add rdx, 128               ; 32 * sizeof(float)
    sub r9, 32
    jnz @@loop
    
    ; 4. Merge low and high accumulators
    vaddps zmm0, zmm0, zmm1
    
    ; 5. Horizontal Add Reduction (ZMM0 -> scalar at [R8])
    vextractf32x8 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0

    vmovss dword ptr [r8], xmm0          
    
    ret
Sovereign_GEMM_Q4_F32 ENDP

END

