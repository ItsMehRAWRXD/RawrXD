; ============================================================================
; rawr_classifier_avx2.asm - AVX2/FMA Accelerated Weight Block Classifier
; ============================================================================
; Processes 8 floats per iteration using 256-bit SIMD.
; Branchless NaN/Inf clearing, bitwise mask accumulation, parallel reductions.
;
; Parameters (Win64 ABI):
;   RCX = const float* w
;   EDX = uint32_t n
;
; Returns: AX = WeightFormat enum value
; ============================================================================

OPTION CASEMAP:NONE

WF_ZERO EQU 0
WF_B1   EQU 1
WF_T3   EQU 3
WF_Q3   EQU 4
WF_Q4   EQU 5
WF_RAW  EQU 255

.CONST
    ALIGN 16
    v_AbsMask  DWORD 8 DUP (7FFFFFFFh)
    ALIGN 16
    v_ExpMask  DWORD 8 DUP (7F800000h)
    ALIGN 16
    c_EpsAVX   REAL4 1.0e-30
    ALIGN 16
    c_B1AVX    REAL4 0.20
    ALIGN 16
    c_T3AVX    REAL4 2.5
    ALIGN 16
    c_Q3AVX    REAL4 6.0

.CODE

PUBLIC ClassifyAVX2

; ----------------------------------------------------------------------------
; WeightFormat ClassifyAVX2(const float* w [RCX], uint32_t n [EDX])
; ----------------------------------------------------------------------------
ClassifyAVX2 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    test    edx, edx
    jz      RetZero

    ; Register Mapping:
    ;   YMM0 = Accumulator sumAbs
    ;   YMM1 = Accumulator maxAbs
    ;   YMM2 = Constant Abs Mask (0x7FFFFFFF)
    ;   YMM3 = Constant Exp Mask (0x7F800000)
    ;   R9D  = Non-zero counter (nz)

    vxorps      ymm0, ymm0, ymm0     ; sumAbs = [0.0 ... 0.0]
    vxorps      ymm1, ymm1, ymm1     ; maxAbs = [0.0 ... 0.0]
    vmovdqa     ymm2, ymmword ptr [v_AbsMask]
    vmovdqa     ymm3, ymmword ptr [v_ExpMask]

    xor         r8d, r8d             ; i = 0
    xor         r9d, r9d             ; nz = 0

    mov         eax, edx
    and         eax, 0FFFFFFF8h      ; Vectorized loop limit (n & ~7)
    jz          ScalarTail           ; If n < 8, handle via scalar loop

AVXLoop:
    ; Load 8 single-precision floats
    vmovups     ymm4, ymmword ptr [rcx + r8*4]

    ; Check NaN/Inf: (u & 0x7F800000) == 0x7F800000
    vpand       ymm5, ymm4, ymm3     ; Extract exponent bits
    vpcmpeqd    ymm5, ymm5, ymm3     ; YMM5 = 0xFFFFFFFF if NaN/Inf, else 0

    ; Extract absolute values
    vpand       ymm6, ymm4, ymm2     ; YMM6 = |x|

    ; Zero out elements that are NaN or Infinity
    vpandn      ymm6, ymm5, ymm6     ; YMM6 = (IsNaNInf) ? 0.0f : |x|

    ; Accumulate sumAbs and maxAbs
    vaddps      ymm0, ymm0, ymm6
    vmaxps      ymm1, ymm1, ymm6

    ; Count non-zero elements: mask = (|x| != 0.0f)
    vxorps      ymm7, ymm7, ymm7
    vcmpneqps   ymm5, ymm6, ymm7     ; Compare non-zero
    vmovmskps   eax, ymm5            ; Get 8-bit mask of non-zero lanes
    popcnt      eax, eax             ; Count set bits
    add         r9d, eax             ; nz += popcnt(mask)

    add         r8d, 8
    cmp         r8d, edx
    jb          AVXLoop

    ; ------------------------------------------------------------------------
    ; Horizontal Reduction for YMM0 (sumAbs) and YMM1 (maxAbs)
    ; ------------------------------------------------------------------------
    vextractf128 xmm4, ymm0, 1
    vaddps      xmm0, xmm0, xmm4
    vhaddps     xmm0, xmm0, xmm0
    vhaddps     xmm0, xmm0, xmm0     ; XMM0[0] = final sumAbs

    vextractf128 xmm4, ymm1, 1
    vmaxps      xmm1, xmm1, xmm4
    vmovhlps    xmm5, xmm1, xmm1
    vmaxps      xmm1, xmm1, xmm5
    vpshufd     xmm5, xmm1, 055h
    vmaxss      xmm1, xmm1, xmm5     ; XMM1[0] = final maxAbs

ScalarTail:
    ; Process remaining elements if n % 8 != 0
    cmp         r8d, edx
    jae         ClassifyStats

    mov         r10d, 7F800000h
    mov         r11d, 7FFFFFFFh

ScalarTailLoop:
    cmp         r8d, edx
    jae         ClassifyStats

    mov         eax, dword ptr [rcx + r8*4]
    mov         edi, eax
    and         edi, r10d
    cmp         edi, r10d
    je          NextTailElement

    and         eax, r11d
    jz          NextTailElement

    inc         r9d
    movd        xmm2, eax
    vaddss      xmm0, xmm0, xmm2     ; sumAbs
    vmaxss      xmm1, xmm1, xmm2     ; maxAbs

NextTailElement:
    inc         r8d
    jmp         ScalarTailLoop

ClassifyStats:
    vzeroupper                       ; Clear upper YMM state before branches

    ; Check if maxAbs == 0.0f
    vxorps      xmm2, xmm2, xmm2
    vcomiss     xmm1, xmm2
    je          RetZero

    ; Calculate metrics
    vcvtsi2ss   xmm2, xmm2, edx      ; float(n)
    vcvtsi2ss   xmm3, xmm3, r9d      ; float(nz)

    ; density = nz / n
    vdivss      xmm4, xmm3, xmm2
    vucomiss    xmm4, dword ptr [c_B1AVX]
    jb          RetB1

    ; meanAbs = sumAbs / n
    vdivss      xmm5, xmm0, xmm2
    vaddss      xmm5, xmm5, dword ptr [c_EpsAVX]

    ; peak = maxAbs / (meanAbs + eps)
    vdivss      xmm6, xmm1, xmm5

    vucomiss    xmm6, dword ptr [c_T3AVX]
    jb          RetT3

    vucomiss    xmm6, dword ptr [c_Q3AVX]
    jb          RetQ3

    mov         ax, WF_Q4
    jmp         Done

RetZero:
    mov         ax, WF_ZERO
    jmp         Done

RetB1:
    mov         ax, WF_B1
    jmp         Done

RetT3:
    mov         ax, WF_T3
    jmp         Done

RetQ3:
    mov         ax, WF_Q3

Done:
    add         rsp, 40
    pop         rsi
    pop         rdi
    pop         rbx
    ret

ClassifyAVX2 ENDP

END
