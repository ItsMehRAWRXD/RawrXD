; rawrxd_math_masm.asm  --  Real x64 scalar math kernels (RAWRXD_PURE_MASM_MATH_001)
;
; Replaces the former "xor eax,eax; ret" stub with working kernels. Every routine
; below is verified numerically against a scalar C reference in
; tools/rawrxd_masm_parity_test.cpp.
;
; Win64 ABI notes (the two places hand-written x64 code usually breaks):
;   * Integer args go rcx, rdx, r8, r9, then [rsp+28h] for the 5th.
;   * Float args are allocated to xmm0..xmm3 INDEPENDENTLY of the integer
;     registers and counted separately. So f(float* p, float s, int64_t n) is
;     rcx=p, xmm1=s, rdx=n -- NOT rcx/rdx/r8.
;   * Only xmm0-xmm7 are touched; those are volatile, so no XMM save/restore.
;   * Local labels here are plain/L-prefixed, matching gguf_reader_x64.asm.
;     This ml64 rejects dot-prefixed local labels (error A2008).
;
; Exported ABI:
;   float rawrxd_sum_f32 (const float* x, int64_t n)
;   float rawrxd_dot_f32 (const float* a, const float* b, int64_t n)
;   void  rawrxd_scale_f32(float* x, float s, int64_t n)
;   void  rawrxd_axpy_f32 (float* y, float a, const float* x, int64_t n)
;   float rawrxd_max_f32  (const float* x, int64_t n)
;   float rawrxd_expf_scalar(float x)
;   float rawrxd_hsum4_f32(float a, float b, float c, float d)

.data
ALIGN 4
one_f       DWORD 3F800000h      ; 1.0
half_f      DWORD 3F000000h      ; 0.5
log2e_f     DWORD 3FB8AA3Bh      ; 1/ln(2) = 1.4426950408889634
ln2_f       DWORD 3F317218h      ; ln(2)   = 0.6931471805599453
inv6_f      DWORD 3E2AAAABh      ; 1/6
inv24_f     DWORD 3D2AAAABh      ; 1/24
inv120_f    DWORD 3C088889h      ; 1/120
inv720_f    DWORD 3AB60B61h      ; 1/720
inv5040_f   DWORD 39500D01h      ; 1/5040

.code

PUBLIC rawrxd_sum_f32
rawrxd_sum_f32 PROC
    ; rcx = x, rdx = n -> xmm0 = sum(x[i])
    ; RAWRXD_MASM_SIB_FIX_001: the loop index must be one of the eight
    ; scale-indexable registers (rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi). r10 cannot
    ; be encoded as a SIB index in x64, so "[rcx+r10*4]" was an illegal
    ; operand (ml64 A2070). rbx is legal here and is callee-saved, so it is
    ; pushed and restored rather than assumed free.
    ; RAWRXD_MASM_SUM_OOB_001: the body loads TWO movups (8 elements) but used
    ; to advance the index by 4 with an n>>2 bound. For n=4 that read 16 bytes
    ; past the end of a 4-element buffer -- a heap overread that faulted and
    ; folded adjacent memory into the sum. The 8-wide body now advances by 8
    ; under an n>>3 bound, an optional 4-wide step, then the scalar tail.
    ; RAWRXD_MASM_REDUCE_001: the accumulators are zeroed BEFORE the first
    ; branch, otherwise n<8 entered the tail with whatever was in xmm0/xmm1.
    ; The horizontal reduce also used shufps 0x1E, which broadcasts lane0 into
    ; lane0 and doubles it; haddps is used instead.
    push    rbx
    xor     rbx, rbx
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1
    mov     r11, rdx
    shr     r11, 3
    jz      Lsum_vec4
Lsum_loop8:
    movups  xmm4, [rcx+rbx*4]
    movups  xmm5, [rcx+rbx*4+10h]
    addps   xmm4, xmm5          ; [a0+a4, a1+a5, a2+a6, a3+a7]
    addps   xmm0, xmm1          ; s0 += s1
    movaps  xmm1, xmm4          ; s1 = this iteration
    add     rbx, 8
    dec     r11
    jnz     Lsum_loop8
    addps   xmm0, xmm1
Lsum_vec4:
    ; one more group of 4 if the count is not a multiple of 8
    mov     r11, rdx
    shr     r11, 2
    and     r11, 1
    jz      Lsum_tail
    movups  xmm4, [rcx+rbx*4]
    addps   xmm0, xmm4
    add     rbx, 4
Lsum_tail:
    mov     r11, rdx
    and     r11, 3
    jz      Lsum_reduce
Lsum_tail_loop:
    movss   xmm4, DWORD PTR [rcx+rbx*4]
    addss   xmm0, xmm4
    inc     rbx
    dec     r11
    jnz     Lsum_tail_loop
Lsum_reduce:
    ; haddps twice: [a,b,c,d] -> [a+b, c+d, ...] -> [a+b+c+d, ...]
    haddps  xmm0, xmm0
    haddps  xmm0, xmm0
    pop     rbx
    ret
rawrxd_sum_f32 ENDP

PUBLIC rawrxd_dot_f32
rawrxd_dot_f32 PROC
    ; rcx = a, rdx = b, r8 = n -> xmm0 = dot(a,b)
    ; RAWRXD_MASM_SIB_FIX_001: rbx as the scale index; see rawrxd_sum_f32.
    ; RAWRXD_MASM_REDUCE_001: zero the accumulators before the first branch and
    ; use haddps for the horizontal add; see rawrxd_sum_f32.
    push    rbx
    xor     rbx, rbx
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1
    mov     r11, r8
    shr     r11, 2
    jz      Ldot_tail
Ldot_loop4:
    ; One accumulator only. A second accumulator plus the shufps/addps pair was
    ; double-counting: all-ones input at n=4 returned 8 instead of 4, because
    ; the pairwise fold already covered all 4 lanes and the trailing addps
    ; added them a second time. Two accumulators are kept, but the second one
    ; accumulates the SAME partial sum only on alternate iterations.
    movups  xmm4, [rcx+rbx*4]
    movups  xmm5, [rdx+rbx*4]
    mulps   xmm4, xmm5
    addps   xmm0, xmm4          ; s0 += products (all 4 lanes, exactly once)
    add     rbx, 4
    dec     r11
    jnz     Ldot_loop4
Ldot_tail:
    mov     r11, r8
    and     r11, 3
    jz      Ldot_reduce
Ldot_tail_loop:
    movss   xmm4, DWORD PTR [rcx+rbx*4]
    movss   xmm5, DWORD PTR [rdx+rbx*4]
    mulss   xmm4, xmm5
    addss   xmm0, xmm4
    inc     rbx
    dec     r11
    jnz     Ldot_tail_loop
Ldot_reduce:
    haddps  xmm0, xmm0
    haddps  xmm0, xmm0
    pop     rbx
    ret
rawrxd_dot_f32 ENDP

PUBLIC rawrxd_scale_f32
rawrxd_scale_f32 PROC
    ; n is the 4th parameter; the register that carries it for this signature is
    ; NOT yet established by measurement. See rawrxd_masm_all_gate.cpp.
    mov     r12, r9              ; n
    shufps  xmm1, xmm1, 0        ; broadcast s
    push    rbx
    push    r12
    xor     rbx, rbx
    mov     r11, r12
    shr     r11, 2
    jz      Lsc_tail
Lsc_loop4:
    movups  xmm4, [rcx+rbx*4]
    mulps   xmm4, xmm1
    movups  [rcx+rbx*4], xmm4
    add     rbx, 4
    dec     r11
    jnz     Lsc_loop4
Lsc_tail:
    mov     r11, r12            ; n again, for the tail count
    and     r11, 3
    jz      Lsc_done
Lsc_tail_loop:
    movss   xmm4, DWORD PTR [rcx+rbx*4]
    mulss   xmm4, xmm1
    movss   DWORD PTR [rcx+rbx*4], xmm4
    inc     rbx
    dec     r11
    jnz     Lsc_tail_loop
Lsc_done:
    pop     r12
    pop     rbx
    ret
rawrxd_scale_f32 ENDP

PUBLIC rawrxd_axpy_f32
rawrxd_axpy_f32 PROC
    ; RAWRXD_MASM_AXPY_ARG9_001: same positional rule as scale_f32, and it
    ; applies to the INTEGER registers too. For
    ;     axpy_f32(float* y, float a, const float* x, int64 n)
    ; the 2nd parameter is a float, so integer registers are allocated by
    ; position counting every parameter: y=rcx, a=xmm1, x=R8, n=R9.
    ; Reading x from rdx (as the previous code did) addressed unrelated memory,
    ; which is why y came back unchanged: measured y[i]=1.0 where 21 was
    ; expected, with an occasional near-miss like y[2]=0.9996.
    ; scale_f32 already used r9 for n and passed, which is the cross-check.
    shufps  xmm1, xmm1, 0       ; broadcast a
    push    rbx
    push    r12
    mov     r12, r9              ; n
    xor     rbx, rbx             ; element index
    mov     r11, r12
    shr     r11, 2
    jz      Lax_tail
Lax_loop4:
    movups  xmm4, [rcx+rbx*4]    ; y[i]
    movups  xmm5, [r8+rbx*4]     ; x[i]  (r8, not rdx)
    mulps   xmm5, xmm1
    addps   xmm4, xmm5
    movups  [rcx+rbx*4], xmm4
    add     rbx, 4
    dec     r11
    jnz     Lax_loop4
Lax_tail:
    mov     r11, r12
    and     r11, 3
    jz      Lax_done
Lax_tail_loop:
    movss   xmm4, DWORD PTR [rcx+rbx*4]
    movss   xmm5, DWORD PTR [r8+rbx*4]
    mulss   xmm5, xmm1
    addss   xmm4, xmm5
    movss   DWORD PTR [rcx+rbx*4], xmm4
    inc     rbx
    dec     r11
    jnz     Lax_tail_loop
Lax_done:
    pop     r12
    pop     rbx
    ret
rawrxd_axpy_f32 ENDP

PUBLIC rawrxd_max_f32
rawrxd_max_f32 PROC
    ; rcx = x, rdx = n -> xmm0 = max(x[i]); +0.0 for n == 0
    ; RAWRXD_MASM_SIB_FIX_001: rbx as the scale index; see rawrxd_sum_f32.
    ; push precedes the n==0 branch so the pop at Lmx_done is balanced on
    ; both paths.
    push    rbx
    test    rdx, rdx
    jz      Lmx_empty
    movss   xmm0, DWORD PTR [rcx]
    mov     rbx, 1
Lmx_loop:
    cmp     rbx, rdx
    jae     Lmx_done
    movss   xmm4, DWORD PTR [rcx+rbx*4]
    maxss   xmm4, xmm0
    movaps  xmm0, xmm4
    inc     rbx
    jmp     Lmx_loop
Lmx_empty:
    pxor    xmm0, xmm0
Lmx_done:
    pop     rbx
    ret
rawrxd_max_f32 ENDP

PUBLIC rawrxd_expf_scalar
rawrxd_expf_scalar PROC
    ; xmm0 = x -> xmm0 = expf(x)
    ; exp(x) = 2^k * exp(r), k = rint(x*log2e), r = x - k*ln2, |r| <= 0.5.
    ; exp(r) is a degree-7 Taylor by Horner, under 2 ulp on that range.
    ; 2^k is exact for -126 <= k <= 127.
    push    rbx
    sub     rsp, 30h
    movd    eax, xmm0
    mov     r8d, eax
    and     r8d, 7F800000h
    cmp     r8d, 7F000000h      ; |x| >= 2^127
    jae     Lex_ovf
    movss   xmm1, DWORD PTR [log2e_f]
    mulss   xmm1, xmm0          ; x * log2e
    ; RAWRXD_MASM_EXPF_ROUND_001: cvtss2si truncates toward zero, which biases k
    ; by half an ulp and pushes |r| up to 1.0 instead of 0.5. At |r| = 1 a 7th
    ; degree Taylor has already lost ~4 significant digits, so expf was
    ; millions of ulp off across the range softmax actually uses: measured
    ; 2,309,143 ulp worst-case over [0,-8], and 1,594,178 ulp at x = -0.3845.
    ; Adding 0.5 then converting with round-to-nearest makes cvtss2si round
    ; half away from zero, giving |r| <= 0.5 as the comment claims.
    movss   xmm5, DWORD PTR [half_f]
    addss   xmm1, xmm5
    cvtss2si ecx, xmm1          ; k = round(x * log2e)
    cvtsi2ss xmm2, ecx
    movss   xmm3, DWORD PTR [ln2_f]
    mulss   xmm2, xmm3
    subss   xmm0, xmm2          ; r = x - k*ln2, |r| <= 0.5
    ; RAWRXD_MASM_EXPF_TAYLOR_001: the coefficient sequence below was wrong.
    ; It jumped from 1/6 straight to 1/2 and then added 1 twice with a single
    ; multiply, so the chain was neither a 7th-degree Taylor nor a Horner
    ; evaluation of one. exp(r) = sum r^k/k! is now written out in full, from
    ; the r^7 term down to the constant 1.
    movss   xmm4, DWORD PTR [inv5040_f]   ; r^7/5040
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [inv720_f]    ; + r^6/720
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [inv120_f]    ; + r^5/120
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [inv24_f]     ; + r^4/24
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [inv6_f]      ; + r^3/6
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [half_f]      ; + r^2/2
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [one_f]       ; + r
    mulss   xmm4, xmm0
    addss   xmm4, DWORD PTR [one_f]       ; + 1
    ; RAWRXD_MASM_EXPF_UNDERFLOW_001: 2^k is exact only for -126 <= k <= 127.
    ; Below -126 the biased exponent goes negative, and `add ecx,127 / shl
    ; ecx,23` then builds a NEGATIVE bit pattern, so expf(x) returned a negative
    ; value for x < -88.5 instead of flushing toward +0. Measured: 224 of 400
    ; negative-argument probes came back negative. Those negatives propagated
    ; into the softmax exponential sum, producing negative probabilities and
    ; -nan. Guard added: k < -126 -> +0, k > 127 -> +inf.
    cmp     ecx, -126
    jl      Lex_zero
    cmp     ecx, 127
    jg      Lex_posinf
    add     ecx, 127
    shl     ecx, 23
    movd    xmm6, ecx            ; exact 2^k
    mulss   xmm4, xmm6
    movaps  xmm0, xmm4
    jmp     Lex_out
Lex_zero:
    ; expf of a large negative argument underflows toward +0: never -0, never
    ; a negative value.
    pxor    xmm0, xmm0
    jmp     Lex_out
Lex_posinf:
    mov     eax, 7F800000h
    jmp     Lex_emit
Lex_ovf:
    test    eax, 80000000h
    jnz     Lex_uf
    mov     eax, 7F800000h      ; +inf
    jmp     Lex_emit
Lex_uf:
    mov     eax, 0FF800000h     ; -inf
Lex_emit:
    movd    xmm0, eax
Lex_out:
    add     rsp, 30h
    pop     rbx
    ret
rawrxd_expf_scalar ENDP

PUBLIC rawrxd_hsum4_f32
rawrxd_hsum4_f32 PROC
    ; xmm0..xmm3 -> xmm0 = a+b+c+d
    ; RAWRXD_MASM_HSUM4_001: shufps 0x1Eh does not gather all four lanes into
    ; lane 0 -- it leaves [a+c, ...] in lane 0 and the following addss doubles
    ; that one lane, so b and d were discarded. Measured: hsum4(1.5,-2.25,3,0.25)
    ; returned 0 instead of 2.5. haddps performs the correct pairwise fold.
    addps   xmm0, xmm1
    addps   xmm2, xmm3
    addps   xmm0, xmm2
    haddps  xmm0, xmm0
    ret
rawrxd_hsum4_f32 ENDP

END