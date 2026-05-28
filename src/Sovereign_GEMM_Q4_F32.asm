; ============================================================================
; Sovereign_GEMM_Q4_F32.asm - Native Q4_0 Inference Kernel
; Parity: PyTorch Q4_0 Linear Operator
; Inputs: RCX=Weights(Q4_0), RDX=Input(F32*), R8=Out(F32), R9=Count(Elements)
; Formula: y = (w - 8) * scale * input
; ============================================================================
OPTION CASEMAP:NONE

.DATA
ALIGN 16
mask_f  DD 16 DUP (00000000Fh)
bias_8  DD 16 DUP (8)

.CODE

; ----------------------------------------------------------------------------
; Sovereign_GEMM_Q4_F32
;   RCX = Weights (Q4_0: 2 bytes F16 scale + 16 bytes nibbles)
;   RDX = Input (F32 pointer)
;   R8  = Out (F32 pointer for result)
;   R9  = Count (Total elements, must be multiple of 32 for this version)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_GEMM_Q4_F32
Sovereign_GEMM_Q4_F32 PROC
    vpxord zmm0, zmm0, zmm0         ; ZMM0 = Accumulator (Result)
    
    ; Load Constants
    vmovdqu32 zmm3, zmmword ptr [bias_8]        ; Fix A2070: Explicit size
    vmovdqu32 zmm5, zmmword ptr [mask_f]        ; Mask 0x0F
    
@@loop:
    ; 1. Load Scale (F16) & Weights (32x 4-bit)
    ; GGUF Q4_0 Block: [F16 scale][16 bytes weight]
    vpbroadcastw ymm1, word ptr [rcx] ; Load Scale and broadcast to all 16 slots of YMM
    vcvtph2ps zmm1, ymm1            ; F16 -> F32 (16 elements)
    
    ; Load 16 bytes (32 nibbles)
    vmovdqu xmm2, xmmword ptr [rcx + 2]       ; 16 bytes = 128 bits
    
    ; Expand 16 bytes into two halves of 16-element processing
    vpmovzxbw ymm4, xmm2            ; 16 bytes -> 16 words in YMM4
    
    ; Let's extract low nibbles for 16 elements
    vpand ymm6, ymm4, ymm5          ; Low nibbles (as words)
    
    ; High nibbles for 16 elements
    vpsrlw ymm4, ymm4, 4
    vpand ymm7, ymm4, ymm5          ; High nibbles (as words)
    
    ; Dequantize: (Val - 8) * Scale
    vpmovzxwd zmm6, ymm6            ; 16 words -> 16 dwords in ZMM6
    vpmovzxwd zmm7, ymm7            ; 16 words -> 16 dwords in ZMM7
    
    vpsubd zmm6, zmm6, zmm3         ; (Val - 8)
    vpsubd zmm7, zmm7, zmm3
    
    vcvtdq2ps zmm6, zmm6           ; Convert 16 dwords to 16 floats in ZMM6
    vcvtdq2ps zmm7, zmm7           ; Convert 16 dwords to 16 floats in ZMM7
    
    vmulps zmm6, zmm6, zmm1        ; * Scale
    vmulps zmm7, zmm7, zmm1        ; * Scale

    ; 3. FMA: Accumulate into Result
    vfmadd231ps zmm0, zmm6, zmmword ptr [rdx]       ; Fix A2070
    vfmadd231ps zmm0, zmm7, zmmword ptr [rdx + 64]  ; Fix A2070
    
    add rcx, 18                    ; Advance Weight ptr (sizeof(block_q4_0) = 18)
    add rdx, 128                   ; Advance Input ptr (32 * 4 bytes)
    sub r9, 32                     ; Decrement count
    jnz @@loop
    
    ; 4. Horizontal Add (Final reduction)
    ; Reduce ZMM0 (16x F32) to 1x F32
    vextractf32x8 ymm1, zmm0, 1     ; Upper 256 bits
    vaddps ymm0, ymm0, ymm1         ; ZMM0[0:255] += ZMM0[256:511]
    
    vextractf128 xmm1, ymm0, 1      ; Upper 128 bits
    vaddps xmm0, xmm0, xmm1
    
    vshufps xmm1, xmm0, xmm0, 04Eh  ; Swap halves
    vaddps xmm0, xmm0, xmm1
    
    vshufps xmm1, xmm0, xmm0, 011h  ; Shift
    vaddps xmm0, xmm0, xmm1
    
    vmovss dword ptr [r8], xmm0     ; Store final sum
    ret
Sovereign_GEMM_Q4_F32 ENDP

END
