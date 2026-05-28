; ============================================================================
; SwarmV29_Macros.inc
; Kyber-1024 AVX-512 Vector Primitives
; ============================================================================

; Vectorized Radix-2 Cooley-Tukey Butterfly
; Bounds: inputs in (-q, q), outputs in (-q, q)
KYBER_BUTTERFLY_32L MACRO ZMM_U, ZMM_V, ZMM_TWID, ZMM_TMP1, ZMM_TMP2, ZMM_Q, ZMM_QINV
    vpmullw     ZMM_TMP1, ZMM_V, ZMM_TWID
    vpmulhw     ZMM_TMP2, ZMM_V, ZMM_TWID

    ; Inline Montgomery-style reduction in 16-bit lanes
    vpmullw     ZMM_V, ZMM_TMP1, ZMM_QINV
    vpmulhw     ZMM_V, ZMM_V, ZMM_Q
    vpsubw      ZMM_TMP2, ZMM_TMP2, ZMM_V

    ; Vector addition/subtraction topology
    vmovdqa64   ZMM_TMP1, ZMM_U
    vpaddw      ZMM_U, ZMM_TMP1, ZMM_TMP2
    vpsubw      ZMM_V, ZMM_TMP1, ZMM_TMP2
ENDM

; Constant-time canonical bounding to [0, q-1]
KYBER_STRICT_NORMALIZE_32L MACRO ZMM_COEFF, ZMM_TMP1, ZMM_TMP2, ZMM_Q
    ; Correct negative values: if coeff < 0, add q
    vpxord      ZMM_TMP1, ZMM_TMP1, ZMM_TMP1
    vpcmpw      k1, ZMM_COEFF, ZMM_TMP1, 1
    vpaddw      ZMM_TMP2, ZMM_COEFF, ZMM_Q
    vpblendmw   ZMM_COEFF{k1}, ZMM_COEFF, ZMM_TMP2

    ; Correct overflow values: if coeff >= q, subtract q
    vpsubw      ZMM_TMP2, ZMM_COEFF, ZMM_Q
    vpcmpw      k1, ZMM_COEFF, ZMM_Q, 5
    vpblendmw   ZMM_COEFF{k1}, ZMM_COEFF, ZMM_TMP2
ENDM
