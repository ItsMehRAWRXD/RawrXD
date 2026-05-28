; ==============================================================================
; SwarmV29_NTT_Butterfly_2x.asm
; PHASE-29d: 2x Unrolled Cooley-Tukey Butterfly (Branchless, Constant-Time)
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Processes TWO independent butterflies in parallel to saturate AVX-512 ports.
; Hides vpmullq latency (~3-5 cycles) by interleaving operations.
;
; Mathematical Logic (in Montgomery space):
;   Butterfly 1: temp1 = Montgomery_Mul(B1, W1), A1' = A1 + temp1, B1' = A1 - temp1
;   Butterfly 2: temp2 = Montgomery_Mul(B2, W2), A2' = A2 + temp2, B2' = A2 - temp2
;
; Register Allocation (2x Unrolled):
;   ZMM0-ZMM1   = A1, A2 (input coefficients)
;   ZMM2-ZMM3   = B1, B2 (input coefficients)
;   ZMM4-ZMM5   = W1, W2 (twiddle factors)
;   ZMM15       = Q (modulus) - PRE-LOADED
;   ZMM16       = Q_INV (Montgomery constant) - PRE-LOADED
;   ZMM6-ZMM14  = Intermediate results (temp, products)
;   K1-K2       = Mask registers for conditional blending
; ==============================================================================

.code

; SwarmV29_NTT_Butterfly_2x
; Inputs:
;   RCX = Pointer to A1 coefficients (64-byte aligned, 8 lanes)
;   RDX = Pointer to B1 coefficients (64-byte aligned, 8 lanes)
;   R8  = Pointer to A2 coefficients (64-byte aligned, 8 lanes)
;   R9  = Pointer to B2 coefficients (64-byte aligned, 8 lanes)
;   [RSP+40] = Pointer to W1 twiddle factors (64-byte aligned)
;   [RSP+48] = Pointer to W2 twiddle factors (64-byte aligned)
;   ZMM15 = Q (modulus) - PRE-LOADED by caller
;   ZMM16 = Q_INV (Montgomery constant) - PRE-LOADED by caller
;
; Returns:
;   [RCX] = A1' (updated coefficients)
;   [RDX] = B1' (updated coefficients)
;   [R8]  = A2' (updated coefficients)
;   [R9]  = B2' (updated coefficients)
;
; Clobbers: ZMM0-ZMM14, K1-K2
; ==============================================================================
ALIGN 16
SwarmV29_NTT_Butterfly_2x PROC PUBLIC
    ; Load twiddle factor pointers
    mov r10, [rsp + 40]         ; r10 = W1 pointer
    mov r11, [rsp + 48]         ; r11 = W2 pointer

    ; ==================================================================
    ; LOAD PHASE: Load all 4 input vectors + 2 twiddle factors
    ; ==================================================================
    vmovdqa64 zmm0, [rcx]       ; zmm0 = A1
    vmovdqa64 zmm1, [r8]        ; zmm1 = A2
    vmovdqa64 zmm2, [rdx]       ; zmm2 = B1
    vmovdqa64 zmm3, [r9]        ; zmm3 = B2
    vmovdqa64 zmm4, [r10]       ; zmm4 = W1
    vmovdqa64 zmm5, [r11]       ; zmm5 = W2

    ; ==================================================================
    ; MONTGOMERY MULTIPLICATION PHASE (INTERLEAVED)
    ; Process B1*W1 and B2*W2 in parallel to hide latency
    ; ==================================================================

    ; --- Butterfly 1: T1 = B1 * W1 ---
    vpmullq zmm6, zmm2, zmm4    ; T1_low = B1 * W1

    ; --- Butterfly 2: T2 = B2 * W2 (interleaved) ---
    vpmullq zmm7, zmm3, zmm5    ; T2_low = B2 * W2

    ; --- Montgomery Reduction for Butterfly 1 ---
    vpmullq zmm8, zmm6, zmm16   ; m1 = T1 * Q_INV
    vpandq  zmm8, zmm8, mask_32bit  ; m1 mod 2^32
    vpmullq zmm9, zmm8, zmm15   ; m1 * Q
    vpaddq  zmm10, zmm6, zmm9   ; T1 + m1*Q
    vpsrlq  zmm6, zmm10, 32     ; temp1 = (T1 + m1*Q) >> 32

    ; --- Montgomery Reduction for Butterfly 2 (interleaved) ---
    vpmullq zmm8, zmm7, zmm16   ; m2 = T2 * Q_INV
    vpandq  zmm8, zmm8, mask_32bit  ; m2 mod 2^32
    vpmullq zmm9, zmm8, zmm15   ; m2 * Q
    vpaddq  zmm10, zmm7, zmm9   ; T2 + m2*Q
    vpsrlq  zmm7, zmm10, 32     ; temp2 = (T2 + m2*Q) >> 32

    ; ==================================================================
    ; BUTTERFLY ARITHMETIC PHASE (INTERLEAVED)
    ; ==================================================================

    ; --- Preserve original A values ---
    vmovdqa64 zmm12, zmm0       ; zmm12 = A1_orig
    vmovdqa64 zmm13, zmm1       ; zmm13 = A2_orig

    ; --- Butterfly 1: A1' = (A1 + temp1) mod Q ---
    vpaddq  zmm10, zmm0, zmm6   ; A1 + temp1
    vpsubq  zmm11, zmm10, zmm15 ; (A1 + temp1) - Q
    vpcmpgtq k1, zmm11, zero_vec
    vpblendmq zmm0{k1}, zmm10, zmm11    ; zmm0 = A1'

    ; --- Butterfly 2: A2' = (A2 + temp2) mod Q (interleaved) ---
    vpaddq  zmm10, zmm1, zmm7   ; A2 + temp2
    vpsubq  zmm11, zmm10, zmm15 ; (A2 + temp2) - Q
    vpcmpgtq k2, zmm11, zero_vec
    vpblendmq zmm1{k2}, zmm10, zmm11    ; zmm1 = A2'

    ; --- Butterfly 1: B1' = (A1_orig - temp1) mod Q ---
    vpsubq  zmm10, zmm12, zmm6  ; A1_orig - temp1
    vpaddq  zmm11, zmm10, zmm15 ; (A1_orig - temp1) + Q
    vpcmpgtq k1, zmm10, zero_vec
    vpblendmq zmm2{k1}, zmm11, zmm10    ; zmm2 = B1'

    ; --- Butterfly 2: B2' = (A2_orig - temp2) mod Q (interleaved) ---
    vpsubq  zmm10, zmm13, zmm7  ; A2_orig - temp2
    vpaddq  zmm11, zmm10, zmm15 ; (A2_orig - temp2) + Q
    vpcmpgtq k2, zmm10, zero_vec
    vpblendmq zmm3{k2}, zmm11, zmm10    ; zmm3 = B2'

    ; ==================================================================
    ; STORE PHASE: Write back all 4 result vectors
    ; ==================================================================
    vmovdqa64 [rcx], zmm0       ; Store A1'
    vmovdqa64 [rdx], zmm2       ; Store B1'
    vmovdqa64 [r8], zmm1        ; Store A2'
    vmovdqa64 [r9], zmm3        ; Store B2'

    ret
SwarmV29_NTT_Butterfly_2x ENDP

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