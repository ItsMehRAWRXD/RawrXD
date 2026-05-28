; ==============================================================================
; SwarmV29_NTT_Butterfly.asm
; PHASE-29: Cooley-Tukey Butterfly Primitive (Branchless, Constant-Time)
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Mathematical Logic (in Montgomery space):
;   temp = Montgomery_Mul(B, W)
;   A'   = (A + temp) mod Q
;   B'   = (A - temp) mod Q
;
; Uses mask-based blending (vpblendmq) instead of branches to prevent
; timing side-channel leakage of secret PQC keys.
; ==============================================================================

.code

; SwarmV29_NTT_Butterfly
; Inputs:
;   ZMM0 = A (Coefficients 1, 8 lanes)
;   ZMM1 = B (Coefficients 2, 8 lanes)
;   ZMM2 = W (Twiddle Factors, 8 lanes)
;   R9   = Q (Modulus)
;   R10  = Q_INV (Montgomery Constant)
;
; Returns:
;   ZMM0 = A' (Updated Coefficients 1)
;   ZMM1 = B' (Updated Coefficients 2)
;
; Clobbers: ZMM3-ZMM13, K1, K2
; ==============================================================================
ALIGN 16
SwarmV29_NTT_Butterfly PROC PUBLIC
    ; --- Montgomery Mul(B, W) -> temp in ZMM3 ---
    vpmullq zmm4, zmm1, zmm2    ; T = B * W
    vpbroadcastq zmm5, r10      ; zmm5 = Q_INV
    vpmullq zmm6, zmm4, zmm5    ; m = T * Q_INV
    vpandq  zmm6, zmm6, mask_32bit  ; m mod 2^32
    vpbroadcastq zmm7, r9       ; zmm7 = Q
    vpmullq zmm8, zmm6, zmm7    ; m * Q
    vpaddq  zmm9, zmm4, zmm8    ; T + m*Q
    vpsrlq  zmm3, zmm9, 32      ; temp = (T + m*Q) >> 32

    ; --- 2. Preserve original A ---
    vmovdqa64 zmm14, zmm0       ; zmm14 = A_orig (backup before overwrite)

    ; --- 3. A' = (A + temp) mod Q ---
    vpaddq  zmm10, zmm0, zmm3   ; A + temp
    vpsubq  zmm11, zmm10, zmm7  ; (A + temp) - Q
    ; If result >= Q, use subtracted value; else use original sum
    vpcmpgtq k1, zmm11, zero_vec   ; k1 = mask where (A+temp)-Q >= 0
    vpblendmq zmm0{k1}, zmm10, zmm11     ; zmm0 = A'

    ; --- 4. B' = (A_orig - temp) mod Q ---
    vpsubq  zmm12, zmm14, zmm3  ; A_orig - temp (CORRECTED: uses backup)
    vpaddq  zmm13, zmm12, zmm7  ; (A_orig - temp) + Q (handle negative)
    ; If A_orig >= temp, result is positive; else add Q
    vpcmpgtq k2, zmm12, zero_vec   ; k2 = mask where A-temp >= 0
    vpblendmq zmm1{k2}, zmm13, zmm12     ; zmm1 = B'

    ret
SwarmV29_NTT_Butterfly ENDP

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
