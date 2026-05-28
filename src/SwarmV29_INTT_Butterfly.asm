; ==============================================================================
; SwarmV29_INTT_Butterfly.asm
; PHASE-29: Inverse Cooley-Tukey Butterfly (Branchless, Constant-Time)
; Target: 70B @ 150TPS via AVX-512 Vectorized INTT
; ------------------------------------------------------------------------------
; Mathematical Logic (in Montgomery space):
;   temp = Montgomery_Mul(B, W_inv)
;   A'   = (A + temp) mod Q
;   B'   = (A - temp) mod Q
;
; The INTT butterfly is identical to the NTT butterfly, but uses the modular
; inverse of the twiddle factor (W_inv = W^-1 mod Q).
;
; Uses mask-based blending (vpblendmq) instead of branches to prevent
; timing side-channel leakage of secret PQC keys.
; ==============================================================================

.code

; SwarmV29_INTT_Butterfly
; Inputs:
;   ZMM0 = A (Coefficients 1, 8 lanes)
;   ZMM1 = B (Coefficients 2, 8 lanes)
;   ZMM2 = W_inv (Inverse Twiddle Factors, 8 lanes)
;   ZMM15 = Q (Modulus) - PRE-LOADED by caller
;   ZMM16 = Q_INV (Montgomery Constant) - PRE-LOADED by caller
;
; Returns:
;   ZMM0 = A' (Updated Coefficients 1)
;   ZMM1 = B' (Updated Coefficients 2)
;
; Clobbers: ZMM3-ZMM14, K1-K2
; ==============================================================================
ALIGN 16
SwarmV29_INTT_Butterfly PROC PUBLIC
    ; --- Montgomery Mul(B, W_inv) -> temp in ZMM3 ---
    vpmullq zmm4, zmm1, zmm2    ; T = B * W_inv
    vpmullq zmm6, zmm4, zmm16   ; m = T * Q_INV (zmm16 = Q_INV)
    vpandq  zmm6, zmm6, mask_32bit  ; m mod 2^32
    vpmullq zmm8, zmm6, zmm15   ; m * Q (zmm15 = Q)
    vpaddq  zmm9, zmm4, zmm8    ; T + m*Q
    vpsrlq  zmm3, zmm9, 32      ; temp = (T + m*Q) >> 32

    ; --- Preserve original A ---
    vmovdqa64 zmm14, zmm0       ; zmm14 = A_orig

    ; --- A' = (A + temp) mod Q ---
    vpaddq  zmm10, zmm0, zmm3   ; A + temp
    vpsubq  zmm11, zmm10, zmm15 ; (A + temp) - Q
    vpcmpgtq k1, zmm11, zero_vec
    vpblendmq zmm0{k1}, zmm10, zmm11    ; zmm0 = A'

    ; --- B' = (A_orig - temp) mod Q ---
    vpsubq  zmm12, zmm14, zmm3  ; A_orig - temp
    vpaddq  zmm13, zmm12, zmm15 ; (A_orig - temp) + Q
    vpcmpgtq k2, zmm12, zero_vec
    vpblendmq zmm1{k2}, zmm13, zmm12    ; zmm1 = B'

    ret
SwarmV29_INTT_Butterfly ENDP

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