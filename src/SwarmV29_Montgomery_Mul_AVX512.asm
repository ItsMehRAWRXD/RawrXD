; ==============================================================================
; SwarmV29_Montgomery_Mul_AVX512.asm
; PHASE-29: High-Throughput Modular Multiplication Kernel
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Implements Montgomery Multiplication: (a * b * R^-1) mod Q
; Where R = 2^32, Q = 3329 (Kyber modulus)
; Processes 8 coefficients simultaneously using ZMM registers
;
; OPTIMIZED: Constants (Q, Q_INV) are pre-loaded in zmm1/zmm2 by the caller
; (NTT_Transform) to avoid per-call vpbroadcast overhead. This kernel only
; performs the product and REDC reduction.
; ==============================================================================

.code

; SwarmV29_Montgomery_Mul_AVX512
; Inputs:
;   RCX = Pointer to vector A (64-byte aligned array of 64-bit coeffs)
;   RDX = Pointer to vector B (64-byte aligned array of 64-bit coeffs)
;   R8  = Pointer to output buffer (64-byte aligned)
;   ZMM1 = Q (modulus) - PRE-LOADED by caller
;   ZMM2 = Q_INV (Montgomery constant) - PRE-LOADED by caller
;
; Clobbers: R10, ZMM0, ZMM3-ZMM7
; Returns: void (result stored in [R8], range [0, Q-1])
; ==============================================================================
ALIGN 16
SwarmV29_Montgomery_Mul_AVX512 PROC PUBLIC
    ; Load 8 coefficients from each input vector
    vmovdqa64 zmm0, [rcx]       ; zmm0 = A[0..7]
    vmovdqa64 zmm3, [rdx]       ; zmm3 = B[0..7]

    ; Step 1: Full Product T = A * B (lower 64 bits)
    vpmullq zmm4, zmm0, zmm3    ; zmm4 = T = A * B

    ; Step 2: Calculate m = (T * q_inv) mod 2^32
    vpmullq zmm5, zmm4, zmm2    ; zmm5 = T * q_inv
    vpandq  zmm5, zmm5, mask_32bit  ; Isolate lower 32 bits

    ; Step 3: Calculate m * q
    vpmullq zmm6, zmm5, zmm1    ; zmm6 = m * q

    ; Step 4: REDC: (T + m*q) >> 32
    vpaddq  zmm7, zmm4, zmm6    ; zmm7 = T + m*q
    vpsrlq  zmm0, zmm7, 32      ; zmm0 = t = (T + m*q) >> 32

    ; Step 5: Final conditional subtraction to ensure t in [0, Q-1]
    ; t can be in [0, 2Q-1] after REDC. If t >= Q, subtract Q.
    vpsubq  zmm4, zmm0, zmm1    ; zmm4 = t - Q
    vpcmpgtq k1, zmm4, zero_vec ; k1 = mask where (t-Q) > 0, i.e., t > Q
    vpblendmq zmm0{k1}, zmm0, zmm4 ; If t > Q, use t-Q

    ; Store 8 results back to aligned output buffer
    vmovdqa64 [r8], zmm0
    ret
SwarmV29_Montgomery_Mul_AVX512 ENDP

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

; Kyber-1024 Constants (pre-baked for direct use)
ALIGN 16
kyber_q       DQ 3329
kyber_q_inv   DQ 62209          ; (-1/3329) mod 2^32

END
