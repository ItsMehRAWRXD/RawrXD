; ==============================================================================
; Sovereign_GEMM_Q4_F32_Pipelined.asm
; Pure x64 MASM - No Dependencies
; AVX-512 Fused GEMM with L1/L2 Software Pipelining
; Breakthrough Phase 4 Native Kernel
; ==============================================================================
OPTION CASEMAP:NONE

.DATA
ALIGN 16
mask_f_p  DD 16 DUP (00000000Fh)
bias_8_p  DD 16 DUP (8)

.CODE

; ----------------------------------------------------------------------------
; Sovereign_GEMM_Q4_F32_Pipelined
;   RCX = Weights (Q4_0: 18-byte blocks)
;   RDX = Input (F32 pointer, 128 bytes per 32 elements)
;   R8  = Out (F32 pointer for result)
;   R9  = Count (Total elements, must be multiple of 32)
; ----------------------------------------------------------------------------
ALIGN 16
PUBLIC Sovereign_GEMM_Q4_F32_Pipelined
Sovereign_GEMM_Q4_F32_Pipelined PROC
    vpxord zmm0, zmm0, zmm0         ; ZMM0 = Accumulator
    
    ; Load Constants
    vmovups zmm3, zmmword ptr [bias_8_p]
    vmovups zmm5, zmmword ptr [mask_f_p]
    
    ; Calculate loop counts
    test r9, r9
    jz   gemm_exit

    ; Pipeline warmup: Prefetch the first 2 iterations (64 elements)
    ; Each iteration: 18 bytes weights, 128 bytes activations
    prefetchnta byte ptr [rcx]
    prefetchnta byte ptr [rcx + 18]
    prefetcht0  byte ptr [rdx]
    prefetcht0  byte ptr [rdx + 128]

ALIGN 16
gemm_loop:
    ; 1. DEQUANTIZATION (Iteration N)
    ; GGUF Q4_0 Block: [F16 scale][16 bytes weight]
    vpbroadcastw ymm1, word ptr [rcx]
    vcvtph2ps zmm1, ymm1            ; F16 -> F32 (16 sub-elements)
    
    ; Load 16 bytes (32 nibbles)
    vmovdqu xmm2, xmmword ptr [rcx + 2]
    
    ; ------------------------------------------------------------------
    ; 2. PIPELINED PREFETCH (Iteration N+4)
    ; ------------------------------------------------------------------
    ; Weighs: 18 * 4 = 72 bytes ahead
    ; Activations: 128 * 4 = 512 bytes ahead
    prefetchnta byte ptr [rcx + 72] 
    prefetcht0  byte ptr [rdx + 512] 

    ; 3. UNPACK NIBBLES
    vpmovzxbw ymm4, xmm2            ; 16 bytes -> 16 words
    vpand ymm6, ymm4, ymm5          ; Low nibbles (words)
    vpsrlw ymm4, ymm4, 4            ; High nibbles
    vpand ymm7, ymm4, ymm5          ; High nibbles (words)
    
    vpmovzxwd zmm6, ymm6            ; 16 words -> 16 floats-to-be
    vpmovzxwd zmm7, ymm7
    
    vpsubd zmm6, zmm6, zmm3         ; (Val - 8)
    vpsubd zmm7, zmm7, zmm3
    
    vcvtdq2ps zmm6, zmm6
    vcvtdq2ps zmm7, zmm7
    
    vmulps zmm6, zmm6, zmm1        ; Apply shared scale
    vmulps zmm7, zmm7, zmm1

    ; ------------------------------------------------------------------
    ; 4. FUSED MULTIPLY-ADD
    ; ------------------------------------------------------------------
    vfmadd231ps zmm0, zmm6, zmmword ptr [rdx]
    vfmadd231ps zmm0, zmm7, zmmword ptr [rdx + 64]

    ; 5. ADVANCE
    add rcx, 18
    add rdx, 128
    sub r9, 32
    jnz gemm_loop

gemm_exit:
    ; 6. HORIZONTAL REDUCTION
    vextractf32x8 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 04Eh
    vaddps xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 011h
    vaddps xmm0, xmm0, xmm1
    
    vmovss dword ptr [r8], xmm0
    ret
Sovereign_GEMM_Q4_F32_Pipelined ENDP

END
