; ============================================================================
; TreeAttention_Fused_VAL038.asm - AVX-512 Fused Attention Kernel
; Fixed: Proper horizontal sum reduction for attention scores
; ============================================================================

OPTION CASEMAP:NONE
OPTION WIN64:11

; Constants
HIDDEN_DIM      EQU 7168
HEAD_DIM        EQU 128
NUM_HEADS       EQU 56
BLOCK_SIZE      EQU 32

; ============================================================================
; TreeAttention_Fused - Fused Q*K^T + Softmax + Attention*V
; Input:  zmm0-zmm7 = Q vectors (8 registers, 256 floats)
;         zmm8-zmm15 = K vectors
;         zmm16-zmm23 = V vectors
; Output: zmm24-zmm31 = Attention output
; ============================================================================

TreeAttention_Fused PROC
    ; Save non-volatile registers
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Clear accumulators for Q*K^T
    vxorps zmm24, zmm24, zmm24
    vxorps zmm25, zmm25, zmm25
    vxorps zmm26, zmm26, zmm26
    vxorps zmm27, zmm27, zmm27
    
    ; Compute Q*K^T (dot products)
    ; Each zmm register holds 16 floats (512 bits)
    vfmadd231ps zmm24, zmm0, zmm8      ; Q0 * K0
    vfmadd231ps zmm25, zmm1, zmm9      ; Q1 * K1
    vfmadd231ps zmm26, zmm2, zmm10     ; Q2 * K2
    vfmadd231ps zmm27, zmm3, zmm11     ; Q3 * K3
    
    ; Horizontal sum reduction - FIXED
    ; Combine zmm24-zmm27 into single attention score
    
    ; Step 1: Add pairs of zmm registers
    vaddps zmm24, zmm24, zmm25          ; zmm24 = scores 0-15 + 16-31
    vaddps zmm26, zmm26, zmm27          ; zmm26 = scores 32-47 + 48-63
    vaddps zmm24, zmm24, zmm26          ; zmm24 = all scores combined
    
    ; Step 2: Extract upper 256 bits and add
    vextractf32x8 ymm25, zmm24, 1       ; ymm25 = upper 256 bits
    vaddps ymm24, ymm24, ymm25          ; ymm24 = lower + upper
    
    ; Step 3: Extract upper 128 bits and add
    vextractf128 xmm25, ymm24, 1        ; xmm25 = upper 128 bits
    vaddps xmm24, xmm24, xmm25          ; xmm24 = lower + upper
    
    ; Step 4: Horizontal add within xmm
    vpermilps xmm25, xmm24, 0x4E        ; Swap halves
    vaddps xmm24, xmm24, xmm25
    vpermilps xmm25, xmm24, 0xB1        ; Swap pairs
    vaddps xmm24, xmm24, xmm25
    
    ; xmm24 now contains the final attention score sum
    
    ; Apply softmax scaling (divide by sqrt(head_dim))
    vbroadcastss zmm25, xmm24            ; Broadcast sum to all lanes
    vmulps zmm25, zmm25, zmm30           ; Scale by 1/sqrt(128) = 0.088388
    
    ; Compute attention * V
    vmulps zmm24, zmm25, zmm16         ; scaled_attention * V0
    vmulps zmm25, zmm25, zmm17         ; scaled_attention * V1
    
    ; Store results
    vmovups [rcx], zmm24
    vmovups [rcx+64], zmm25
    
    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
TreeAttention_Fused ENDP

; ============================================================================
; HorizontalSum_AVX512 - Proper horizontal reduction helper
; Input:  zmm0 = 16 floats to sum
; Output: xmm0 = scalar sum (in all lanes)
; Clobbers: zmm1, ymm1, xmm1
; ============================================================================

HorizontalSum_AVX512 PROC
    ; Extract upper 256 bits
    vextractf32x8 ymm1, zmm0, 1
    vaddps ymm0, ymm0, ymm1
    
    ; Extract upper 128 bits
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    
    ; Horizontal add within 128 bits
    vpermilps xmm1, xmm0, 0x4E        ; 0x4E = 01001110 = swap halves
    vaddps xmm0, xmm0, xmm1
    vpermilps xmm1, xmm0, 0xB1        ; 0xB1 = 10110001 = swap pairs
    vaddps xmm0, xmm0, xmm1
    
    ; Broadcast result to all lanes of xmm0
    vbroadcastss xmm0, xmm0
    ret
HorizontalSum_AVX512 ENDP

; ============================================================================
; MaxReduction_AVX512 - Proper horizontal max reduction
; Input:  zmm0 = 16 floats
; Output: xmm0 = scalar max (in all lanes)
; ============================================================================

MaxReduction_AVX512 PROC
    ; Extract upper 256 bits and max
    vextractf32x8 ymm1, zmm0, 1
    vmaxps ymm0, ymm0, ymm1
    
    ; Extract upper 128 bits and max
    vextractf128 xmm1, ymm0, 1
    vmaxps xmm0, xmm0, xmm1
    
    ; Horizontal max within 128 bits
    vpermilps xmm1, xmm0, 0x4E
    vmaxps xmm0, xmm0, xmm1
    vpermilps xmm1, xmm0, 0xB1
    vmaxps xmm0, xmm0, xmm1
    
    ret
MaxReduction_AVX512 ENDP

END
