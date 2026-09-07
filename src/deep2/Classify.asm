; =============================================================================
; Classify.asm — Zero-dependency x64 MASM weight format classifier
; Microsoft x64 Calling Convention: RCX=w, EDX=n, return AX
; No CRT, no allocators, no external dependencies.
; =============================================================================

OPTION CASEMAP:NONE

PUBLIC Classify

.const
    align 16
    c_eps   REAL4 1.0e-30
    c_0_20  REAL4 0.20
    c_2_5   REAL4 2.5
    c_6_0   REAL4 6.0

.code

Classify PROC
    ; Early exit: n == 0 -> WF_ZERO
    test    edx, edx
    jz      return_zero

    xorps   xmm0, xmm0          ; maxAbs = 0.0f
    xorps   xmm1, xmm1          ; sumAbs = 0.0f
    xor     r9d, r9d            ; nz = 0
    xor     r8d, r8d            ; i = 0
    mov     r10d, 07F800000h    ; NaN/Inf exponent mask

ALIGN 16
loop_start:
    cmp     r8d, edx
    jae     loop_end

    mov     eax, DWORD PTR [rcx+r8*4]

    ; NaN / Inf check
    mov     r11d, eax
    and     r11d, r10d
    cmp     r11d, r10d
    je      next_iter

    ; Absolute value
    and     eax, 07FFFFFFFh
    test    eax, eax
    jz      next_iter

    inc     r9d
    movd    xmm2, eax
    addss   xmm1, xmm2
    maxss   xmm0, xmm2

next_iter:
    inc     r8d
    jmp     loop_start

loop_end:
    ; maxAbs == 0 ?
    xorps   xmm2, xmm2
    comiss  xmm0, xmm2
    je      return_zero

    cvtsi2ss xmm3, edx          ; float(n)
    cvtsi2ss xmm4, r9d          ; float(nz)

    divss   xmm4, xmm3          ; density
    divss   xmm1, xmm3          ; meanAbs
    addss   xmm1, REAL4 PTR [c_eps]

    movaps  xmm5, xmm0
    divss   xmm5, xmm1          ; peak

    comiss  xmm4, REAL4 PTR [c_0_20]
    jb      return_b1

    comiss  xmm5, REAL4 PTR [c_2_5]
    jb      return_t3

    comiss  xmm5, REAL4 PTR [c_6_0]
    jb      return_q3

    mov     ax, 5
    ret

return_zero:
    xor     eax, eax
    ret

return_b1:
    mov     ax, 1
    ret

return_t3:
    mov     ax, 3
    ret

return_q3:
    mov     ax, 4
    ret

Classify ENDP

END
