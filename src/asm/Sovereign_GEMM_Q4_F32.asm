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
    mask_f  DD 16 DUP (0000000Fh)
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
    push rbx
    vpxord zmm0, zmm0, zmm0     ; ZMM0 = Accumulator (Result)
    vmovups zmm5, zmmword ptr [mask_f]
    vmovups zmm6, zmmword ptr [bias_8]

@@loop:
    ; 1. Load Scale (F16) & Broadcast to ZMM1
    vpbroadcastw ymm1, word ptr [rcx]
    vcvtph2ps zmm1, ymm1       ; ZMM1 = Scale (broadcasted)

    ; 2. Load 32 weights (16 bytes)
    vmovdqu xmm2, xmmword ptr [rcx + 2]
    
    ; 3. Unpack bytes to words (16 bytes -> 16 words in YMM2)
    vpmovzxbw ymm2, xmm2
    
    ; 4. Process Low Nibbles (Elements 0..15)
    vpandd ymm3, ymm2, ymm5 ; Low 4 bits
    vpmovzxwd zmm3, ymm3       ; words -> dwords
    vpsubd zmm3, zmm3, zmm6 ; (w - 8)
    vcvtdq2ps zmm3, zmm3       ; dword -> float
    vmulps zmm3, zmm3, zmm1    ; * scale
    vfmadd231ps zmm0, zmm3, zmmword ptr [rdx]

    ; 5. Process High Nibbles (Elements 16..31)
    vpsrlw ymm4, ymm2, 4       ; Shift right by 4
    vpandd ymm4, ymm4, ymm5
    vpmovzxwd zmm4, ymm4       ; words -> dwords
    vpsubd zmm4, zmm4, zmm6 ; (w - 8)
    vcvtdq2ps zmm4, zmm4
    vmulps zmm4, zmm4, zmm1
    vfmadd231ps zmm0, zmm4, zmmword ptr [rdx + 64]
    
    add rcx, 18                ; sizeof(block_q4_0)
    add rdx, 128               ; 32 * sizeof(float)
    sub r9, 32
    jnz @@loop
    
    ; 6. Horizontal Add Reduction (ZMM0 -> R8)
    vextractf32x8 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 04Eh ; 01|00|11|10
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 011h ; 00|00|01|01
    vaddss xmm0, xmm0, xmm1

    vmovss dword ptr [r8], xmm0          
    
    pop rbx
    ret
Sovereign_GEMM_Q4_F32 ENDP

END

