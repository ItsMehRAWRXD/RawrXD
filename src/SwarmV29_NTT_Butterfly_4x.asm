; ==============================================================================
; SwarmV29_NTT_Butterfly_4x.asm
; PHASE-29d: 4x Unrolled Cooley-Tukey Butterfly (Branchless, Constant-Time)
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Processes FOUR independent butterflies in parallel to maximize AVX-512
; execution port saturation. Hides vpmullq latency (~3-5 cycles) by interleaving
; operations across 4 butterfly pairs.
;
; Register Allocation (4x Unrolled):
;   ZMM0-ZMM3   = A1, A2, A3, A4 (input coefficients)
;   ZMM4-ZMM7   = B1, B2, B3, B4 (input coefficients)
;   ZMM8-ZMM11  = W1, W2, W3, W4 (twiddle factors)
;   ZMM15       = Q (modulus) - PRE-LOADED
;   ZMM16       = Q_INV (Montgomery constant) - PRE-LOADED
;   ZMM12-ZMM31 = Intermediate results (uses upper ZMMs to avoid spills)
;   K1-K4       = Mask registers for conditional blending
; ==============================================================================

.code

; SwarmV29_NTT_Butterfly_4x
; Inputs:
;   RCX = Pointer to A coefficients array (64-byte aligned, 4 x 8 lanes)
;   RDX = Pointer to B coefficients array (64-byte aligned, 4 x 8 lanes)
;   R8  = Pointer to W twiddle factors array (64-byte aligned, 4 x 8 lanes)
;   ZMM15 = Q (modulus) - PRE-LOADED by caller
;   ZMM16 = Q_INV (Montgomery constant) - PRE-LOADED by caller
;
; Returns:
;   [RCX + 0]   = A1' (updated coefficients)
;   [RCX + 64]  = A2' (updated coefficients)
;   [RCX + 128] = A3' (updated coefficients)
;   [RCX + 192] = A4' (updated coefficients)
;   [RDX + 0]   = B1' (updated coefficients)
;   [RDX + 64]  = B2' (updated coefficients)
;   [RDX + 128] = B3' (updated coefficients)
;   [RDX + 192] = B4' (updated coefficients)
;
; Clobbers: ZMM0-ZMM31, K1-K4
; ==============================================================================
ALIGN 16
SwarmV29_NTT_Butterfly_4x PROC PUBLIC
    ; ==================================================================
    ; LOAD PHASE: Load all 8 input vectors + 4 twiddle factors
    ; ==================================================================
    vmovdqa64 zmm0, [rcx +   0]    ; zmm0 = A1
    vmovdqa64 zmm1, [rcx +  64]    ; zmm1 = A2
    vmovdqa64 zmm2, [rcx + 128]    ; zmm2 = A3
    vmovdqa64 zmm3, [rcx + 192]    ; zmm3 = A4

    vmovdqa64 zmm4, [rdx +   0]    ; zmm4 = B1
    vmovdqa64 zmm5, [rdx +  64]    ; zmm5 = B2
    vmovdqa64 zmm6, [rdx + 128]    ; zmm6 = B3
    vmovdqa64 zmm7, [rdx + 192]    ; zmm7 = B4

    vmovdqa64 zmm8,  [r8 +   0]    ; zmm8  = W1
    vmovdqa64 zmm9,  [r8 +  64]    ; zmm9  = W2
    vmovdqa64 zmm10, [r8 + 128]    ; zmm10 = W3
    vmovdqa64 zmm11, [r8 + 192]    ; zmm11 = W4

    ; ==================================================================
    ; MONTGOMERY MULTIPLICATION PHASE (4x INTERLEAVED)
    ; Process B1*W1, B2*W2, B3*W3, B4*W4 in parallel
    ; ==================================================================

    ; --- Stage 1: Full Products ---
    vpmullq zmm17, zmm4, zmm8     ; T1 = B1 * W1
    vpmullq zmm18, zmm5, zmm9     ; T2 = B2 * W2
    vpmullq zmm19, zmm6, zmm10    ; T3 = B3 * W3
    vpmullq zmm20, zmm7, zmm11    ; T4 = B4 * W4

    ; --- Stage 2: Montgomery Reduction (interleaved) ---
    vpmullq zmm21, zmm17, zmm16   ; m1 = T1 * Q_INV
    vpmullq zmm22, zmm18, zmm16   ; m2 = T2 * Q_INV
    vpmullq zmm23, zmm19, zmm16   ; m3 = T3 * Q_INV
    vpmullq zmm24, zmm20, zmm16   ; m4 = T4 * Q_INV

    vpandq  zmm21, zmm21, mask_32bit  ; m1 mod 2^32
    vpandq  zmm22, zmm22, mask_32bit  ; m2 mod 2^32
    vpandq  zmm23, zmm23, mask_32bit  ; m3 mod 2^32
    vpandq  zmm24, zmm24, mask_32bit  ; m4 mod 2^32

    vpmullq zmm25, zmm21, zmm15   ; m1 * Q
    vpmullq zmm26, zmm22, zmm15   ; m2 * Q
    vpmullq zmm27, zmm23, zmm15   ; m3 * Q
    vpmullq zmm28, zmm24, zmm15   ; m4 * Q

    vpaddq  zmm17, zmm17, zmm25   ; T1 + m1*Q
    vpaddq  zmm18, zmm18, zmm26   ; T2 + m2*Q
    vpaddq  zmm19, zmm19, zmm27   ; T3 + m3*Q
    vpaddq  zmm20, zmm20, zmm28   ; T4 + m4*Q

    vpsrlq  zmm17, zmm17, 32      ; temp1 = (T1 + m1*Q) >> 32
    vpsrlq  zmm18, zmm18, 32      ; temp2 = (T2 + m2*Q) >> 32
    vpsrlq  zmm19, zmm19, 32      ; temp3 = (T3 + m3*Q) >> 32
    vpsrlq  zmm20, zmm20, 32      ; temp4 = (T4 + m4*Q) >> 32

    ; ==================================================================
    ; BUTTERFLY ARITHMETIC PHASE (4x INTERLEAVED)
    ; ==================================================================

    ; --- Preserve original A values ---
    vmovdqa64 zmm29, zmm0         ; zmm29 = A1_orig
    vmovdqa64 zmm30, zmm1         ; zmm30 = A2_orig
    vmovdqa64 zmm31, zmm2         ; zmm31 = A3_orig
    ; zmm3 = A4_orig (already in place, we'll use it directly)

    ; --- A' = (A + temp) mod Q (4x parallel) ---
    vpaddq  zmm21, zmm0, zmm17    ; A1 + temp1
    vpaddq  zmm22, zmm1, zmm18    ; A2 + temp2
    vpaddq  zmm23, zmm2, zmm19    ; A3 + temp3
    vpaddq  zmm24, zmm3, zmm20    ; A4 + temp4

    vpsubq  zmm25, zmm21, zmm15   ; (A1 + temp1) - Q
    vpsubq  zmm26, zmm22, zmm15   ; (A2 + temp2) - Q
    vpsubq  zmm27, zmm23, zmm15   ; (A3 + temp3) - Q
    vpsubq  zmm28, zmm24, zmm15   ; (A4 + temp4) - Q

    vpcmpgtq k1, zmm25, zero_vec
    vpcmpgtq k2, zmm26, zero_vec
    vpcmpgtq k3, zmm27, zero_vec
    vpcmpgtq k4, zmm28, zero_vec

    vpblendmq zmm0{k1}, zmm21, zmm25    ; zmm0 = A1'
    vpblendmq zmm1{k2}, zmm22, zmm26    ; zmm1 = A2'
    vpblendmq zmm2{k3}, zmm23, zmm27    ; zmm2 = A3'
    vpblendmq zmm3{k4}, zmm24, zmm28    ; zmm3 = A4'

    ; --- B' = (A_orig - temp) mod Q (4x parallel) ---
    vpsubq  zmm21, zmm29, zmm17   ; A1_orig - temp1
    vpsubq  zmm22, zmm30, zmm18   ; A2_orig - temp2
    vpsubq  zmm23, zmm31, zmm19   ; A3_orig - temp3
    vpsubq  zmm24, zmm3, zmm20    ; A4_orig - temp4 (zmm3 still holds A4_orig)

    vpaddq  zmm25, zmm21, zmm15   ; (A1_orig - temp1) + Q
    vpaddq  zmm26, zmm22, zmm15   ; (A2_orig - temp2) + Q
    vpaddq  zmm27, zmm23, zmm15   ; (A3_orig - temp3) + Q
    vpaddq  zmm28, zmm24, zmm15   ; (A4_orig - temp4) + Q

    vpcmpgtq k1, zmm21, zero_vec
    vpcmpgtq k2, zmm22, zero_vec
    vpcmpgtq k3, zmm23, zero_vec
    vpcmpgtq k4, zmm24, zero_vec

    vpblendmq zmm4{k1}, zmm25, zmm21    ; zmm4 = B1'
    vpblendmq zmm5{k2}, zmm26, zmm22    ; zmm5 = B2'
    vpblendmq zmm6{k3}, zmm27, zmm23    ; zmm6 = B3'
    vpblendmq zmm7{k4}, zmm28, zmm24    ; zmm7 = B4'

    ; ==================================================================
    ; STORE PHASE: Write back all 8 result vectors
    ; ==================================================================
    vmovdqa64 [rcx +   0], zmm0   ; Store A1'
    vmovdqa64 [rcx +  64], zmm1   ; Store A2'
    vmovdqa64 [rcx + 128], zmm2   ; Store A3'
    vmovdqa64 [rcx + 192], zmm3   ; Store A4'

    vmovdqa64 [rdx +   0], zmm4   ; Store B1'
    vmovdqa64 [rdx +  64], zmm5   ; Store B2'
    vmovdqa64 [rdx + 128], zmm6   ; Store B3'
    vmovdqa64 [rdx + 192], zmm7   ; Store B4'

    ret
SwarmV29_NTT_Butterfly_4x ENDP

.data
ALIGN 16
mask_32bit DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh
           DQ 0FFFFFFFFh

ALIGN 16
zero_vec   DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0
           DQ 0

END