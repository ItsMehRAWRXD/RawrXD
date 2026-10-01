; rawrxd_transformer_masm_fixed.asm  --  Real x64 transformer primitives
; (RAWRXD_PURE_MASM_TRANSFORMER_001)
;
; Replaces the former "xor eax,eax; ret" stub. The quantised block layouts below
; are NOT invented: they are taken from the reference blocks already validated by
; gguf_reader_x64.asm's --selftest (src/masm/gguf_reader_x64.asm:139-148):
;   Q8_0 block = f16 d, then 32 int8 quantisers      (34 bytes)
;   Q4_0 block = f16 d, then 16 packed nibble bytes  (18 bytes)
; Q4_0 element 2j is the low nibble of byte j, 2j+1 the high nibble, and each
; nibble is (element & 7) + 8 so the decoded value is (nibble - 8) * d.
;
; Exported ABI:
;   int   rawrxd_q8_0_dequant(const void* blocks, int64_t nblocks, float* out)
;   int   rawrxd_q4_0_dequant(const void* blocks, int64_t nblocks, float* out)
;   float rawrxd_f16_to_f32(unsigned short h)
;   void  rawrxd_softmax_inplace(float* x, int64_t n)
;   void  rawrxd_rmsnorm(float* out, const float* x, int64_t n, float eps)
;   int   rawrxd_is_finite_f32(const float* x, int64_t n)
;
; Win64 notes for this file:
;   * Integer args rcx/rdx/r8/r9; float args in xmm0..xmm3 counted SEPARATELY,
;     so rmsnorm is rcx=out, rdx=x, r8=n, xmm0=eps.
;   * rawrxd_f16_to_f32 is called internally and clobbers every volatile
;     register, so anything live across that call lives in rbx/rsi/rdi/r12/r13.
;   * Scalar SSE memory operands need an explicit DWORD PTR with this ml64.
;   * Local labels are plain/L-prefixed; this ml64 rejects dot-prefixed labels.

; defined in rawrxd_math_masm.asm (same module set, separate TU)
EXTERN rawrxd_max_f32:PROC
EXTERN rawrxd_expf_scalar:PROC
EXTERN rawrxd_sum_f32:PROC
EXTERN rawrxd_dot_f32:PROC

.data
ALIGN 4
one_f        DWORD 3F800000h

.code

; ---------------------------------------------------------------------------
; float rawrxd_f16_to_f32(unsigned short h)
; Win64: the single argument arrives in ecx, NOT edx. Reading edx returned
; whatever happened to be there, which made every conversion return 0 when
; called from C. Handles subnormals, zero, +/-inf and NaN.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_f16_to_f32
rawrxd_f16_to_f32 PROC
    movzx   r8d, cx
    shr     r8d, 10              ; exponent
    and     r8d, 1Fh
    movzx   r9d, cx
    and     r9d, 3FFh            ; mantissa is 10 bits. The mask was 7FFFh,
                                 ; which let the exponent bits leak into the
                                 ; mantissa: 0x7C00 masked to 0x7C00 (nonzero),
                                 ; so +inf was classified as NaN.
    mov     eax, ecx
    shl     eax, 16
    and     eax, 80000000h       ; sign
    mov     r10d, eax            ; r10 = sign bits
    test    r8d, r8d
    jz      Lf16_subnormal
    cmp     r8d, 1Fh
    jae     Lf16_special
    add     r8d, 112             ; e - 15 + 127
    shl     r8d, 23
    or      r10d, r8d
    shl     r9d, 13              ; mantissa into the f32 field
    or      r10d, r9d
    jmp     Lf16_emit
Lf16_subnormal:
    test    r9d, r9d
    jz      Lf16_emit            ; true +/-0: sign only
    ; Normalise: shift the mantissa left until bit 10 is set. A binary16
    ; subnormal is man * 2^-24. With man normalised so bit 10 is set, the value
    ; is (man_norm/1024) * 2^(-14-shift), and man_norm/1024 lies in [1,2), so
    ; the f32 biased exponent is (-14-shift) + 127 = 113 - shift. An earlier
    ; version used (shift + 113), the sign inverted, making every subnormal
    ; wildly wrong (0x0001 became 1/16 instead of 2^-24).
    xor     r11d, r11d
Lf16_sn_loop:
    test    r9d, 400h
    jnz     Lf16_sn_emit
    shl     r9d, 1
    inc     r11d
    jmp     Lf16_sn_loop
Lf16_sn_emit:
    mov     r8d, 113
    sub     r8d, r11d
    shl     r8d, 23
    and     r9d, 3FFh
    shl     r9d, 13
    or      r10d, r8d
    or      r10d, r9d
    jmp     Lf16_emit
Lf16_special:
    ; The mantissa is tested BEFORE it is shifted, so inf (mantissa 0) and
    ; NaN (mantissa != 0) are distinguished correctly.
    test    r9d, r9d
    jnz     Lf16_nan
    mov     r10d, 7F800000h      ; +/-inf
    jmp     Lf16_emit
Lf16_nan:
    mov     r10d, 7FC00000h      ; quiet NaN
Lf16_emit:
    or      r10d, eax            ; apply the sign bit
    movd    xmm0, r10d
    ret
rawrxd_f16_to_f32 ENDP

; ---------------------------------------------------------------------------
; int rawrxd_q8_0_dequant(const void* blocks, int64_t nblocks, float* out)
; Returns elements written (nblocks * 32), or 0 for nblocks == 0.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_q8_0_dequant
rawrxd_q8_0_dequant PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    mov     rbx, rcx             ; current block
    mov     rsi, r8              ; out cursor
    mov     rdi, rdx             ; blocks remaining
    xor     r12d, r12d           ; total elements
    test    rdi, rdi
    jz      Lq8_done
Lq8_block:
    movzx   ecx, WORD PTR [rbx]
    call    rawrxd_f16_to_f32    ; xmm0 = d
    add     rbx, 2
    ; RAWRXD_MASM_PMOVSX_001: the previous vectorised body used pmovsxbd, whose
    ; operand semantics this ml64 would not verify in isolation, and a
    ; movq(8 bytes) fed to the 4-byte form discarded half the quantisers.
    ; The scalar loop below is obviously correct and is the one the parity test
    ; measures: out[q] = (int8)q[j] * d for j = 0..31.
    xor     r14d, r14d
Lq8_elem:
    movsx   eax, BYTE PTR [rbx+r14]
    cvtsi2ss xmm1, eax
    mulss   xmm1, xmm0
    movss   DWORD PTR [rsi+r14*4], xmm1
    inc     r14
    cmp     r14, 32
    jb      Lq8_elem
    add     rbx, 32
    add     rsi, 128
    add     r12d, 32
    dec     rdi
    jnz     Lq8_block
Lq8_done:
    mov     eax, r12d
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_q8_0_dequant ENDP

; ---------------------------------------------------------------------------
; int rawrxd_q4_0_dequant(const void* blocks, int64_t nblocks, float* out)
; Scalar nibble unpack; value = (nibble - 8) * d. Returns nblocks * 32.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_q4_0_dequant
rawrxd_q4_0_dequant PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    mov     rbx, rcx             ; current block
    mov     rsi, r8              ; out cursor
    mov     rdi, rdx             ; blocks remaining
    xor     r12d, r12d           ; total elements
    test    rdi, rdi
    jz      Lq4_done
Lq4_block:
    movzx   ecx, WORD PTR [rbx]
    call    rawrxd_f16_to_f32    ; xmm0 = d
    add     rbx, 2
    xor     r13d, r13d           ; byte counter 0..15
    xor     r9d, r9d             ; element index inside block
Lq4_byte:
    movzx   eax, BYTE PTR [rbx+r13]
    mov     ecx, eax
    and     ecx, 0Fh             ; element 2j   = low nibble
    sub     ecx, 8
    cvtsi2ss xmm1, ecx
    mulss   xmm1, xmm0
    movss   DWORD PTR [rsi+r9*4], xmm1
    inc     r9
    shr     eax, 4               ; element 2j+1 = high nibble
    sub     eax, 8
    cvtsi2ss xmm1, eax
    mulss   xmm1, xmm0
    movss   DWORD PTR [rsi+r9*4], xmm1
    inc     r9
    inc     r13
    cmp     r13, 16
    jb      Lq4_byte
    add     rbx, 16
    add     rsi, 128
    add     r12d, 32
    dec     rdi
    jnz     Lq4_block
Lq4_done:
    mov     eax, r12d
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_q4_0_dequant ENDP

; ---------------------------------------------------------------------------
; void rawrxd_softmax_inplace(float* x, int64_t n)
; max-subtract, exp, normalize. All state lives in callee-saved registers
; because rawrxd_expf_scalar clobbers every volatile register.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_softmax_inplace
rawrxd_softmax_inplace PROC
    ; RAWRXD_MASM_SOFTMAX_SLOT_001: max and the exponential sum were spilled to
    ; [rsp+00h] and [rsp+04h] and read back AFTER two calls (rawrxd_max_f32,
    ; rawrxd_expf_scalar, rawrxd_sum_f32). Each call pushes a return address, so
    ; rsp is lower at the read than at the store and those slots no longer hold
    ; what was written -- they alias the return-address area. Measured: every
    ; n produced -nan or a non-unit sum; FIRST_BAD was n=1 with got=-nan.
    ; Both values now live in callee-saved registers (r12 = max, r13 = sum),
    ; which survive every call, so no stack slot has to outlive a call.
    ; NOTE: this signature is (float* x, int64_t n) with NO float parameter, so
    ; the MSVC xmm3 argument-placement defect that affected rmsnorm does not
    ; apply here. Verified by inspection.
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 20h
    mov     rbx, rcx             ; x
    mov     rsi, rcx
    mov     rdi, rdx             ; n
    test    rdi, rdi
    jz      Lsm_done
    mov     r14, rdi             ; n, callee-saved: the loop bound
    mov     rdx, r14
    call    rawrxd_max_f32       ; xmm0 = max
    movd    r12d, xmm0           ; max, callee-saved
    xor     r9, r9
Lsm_sub:
    cmp     r9, r14
    jae     Lsm_exp
    movss   xmm0, DWORD PTR [rsi+r9*4]
    movd    xmm1, r12d
    subss   xmm0, xmm1           ; x[i] - max
    call    rawrxd_expf_scalar
    movss   DWORD PTR [rsi+r9*4], xmm0
    inc     r9
    jmp     Lsm_sub
Lsm_exp:
    mov     rcx, rsi
    mov     rdx, r14
    call    rawrxd_sum_f32       ; xmm0 = sum of exponentials
    movd    r13d, xmm0           ; sum, callee-saved
    xor     r9, r9
Lsm_norm:
    cmp     r9, r14              ; bound is n (r14), not the sum (r13)
    jae     Lsm_done
    movss   xmm0, DWORD PTR [rsi+r9*4]
    movd    xmm1, r13d
    divss   xmm0, xmm1           ; x[i] / sum
    movss   DWORD PTR [rsi+r9*4], xmm0
    inc     r9
    jmp     Lsm_norm
Lsm_done:
    add     rsp, 20h
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_softmax_inplace ENDP

; ---------------------------------------------------------------------------
; void rawrxd_rmsnorm(float* out, const float* x, int64_t n, float eps)
; rcx=out, rdx=x, r8=n, xmm0=eps.  rms = sqrt(dot(x,x)/n + eps)
; ---------------------------------------------------------------------------
PUBLIC rawrxd_rmsnorm
rawrxd_rmsnorm PROC
    ; RAWRXD_MASM_EPS_XMM3_001: eps arrives in xmm3, NOT xmm0. MSVC assigns
    ; float arguments to xmm0..xmm3 by their POSITION in the parameter list,
    ; counting the integer parameters. rawrxd_rmsnorm has three integer
    ; parameters (out, x, n), so the 4th parameter's float lands in xmm3.
    ; Verified with a probe of the identical four-parameter shape:
    ;   xmm0=0x3F800000 xmm1=0 xmm2=0 xmm3=0x40800000 (eps=4.0f)
    ; Reading xmm0 yielded 1.0, so the +eps term contributed nothing.
    ; This also corrects an earlier misdiagnosis: the first repair blamed the
    ; return address aliasing the [rsp] save slot, and a second blamed
    ; DAZ/FTZ. Neither was the cause. The stack slot is still avoided, because
    ; keeping eps in a callee-saved register across the call is correct either
    ; way, but the actual defect was the wrong argument register.
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 20h
    mov     rbx, rcx             ; out
    mov     rsi, rdx             ; x
    mov     rdi, r8              ; n
    movd    r12d, xmm3           ; eps -- 4th parameter, so xmm3
    test    rdi, rdi
    jz      Lrm_done
    mov     rcx, rsi
    mov     rdx, rsi
    mov     r8, rdi
    call    rawrxd_dot_f32       ; xmm0 = dot(x,x)
    ; RAWRXD_MASM_RDI_VOLATILE_001: n was held in rdi across the call, but rdi
    ; is volatile on Win64 and rawrxd_dot_f32 may clobber it. The transform loop
    ; then compared against a corrupted bound and stopped early: measured, only
    ; n-1 elements were written, so the last one or two stayed at the caller's
    ; fill value (FIRST_BAD_INDEX=30 for n=31, 31 for n=32). n and the loop
    ; counter now live in callee-saved r13 and rbx is already the out pointer,
    ; so the counter uses r12's sibling register.
    mov     r13, rdi             ; n, safe across the call
    cvtsi2ss xmm1, r13
    divss   xmm0, xmm1           ; mean of squares
    movd    xmm5, r12d
    addss   xmm0, xmm5
    sqrtss  xmm0, xmm0           ; rms
    movss   xmm3, DWORD PTR [one_f]
    divss   xmm3, xmm0           ; 1/rms
    shufps  xmm3, xmm3, 0        ; broadcast
    xor     r9, r9
Lrm_loop:
    cmp     r9, r13
    jae     Lrm_done
    movss   xmm4, DWORD PTR [rsi+r9*4]
    mulss   xmm4, xmm3
    movss   DWORD PTR [rbx+r9*4], xmm4
    inc     r9
    jmp     Lrm_loop
Lrm_done:
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_rmsnorm ENDP

; ---------------------------------------------------------------------------
; int rawrxd_is_finite_f32(const float* x, int64_t n)  -> 1 if all finite
; ---------------------------------------------------------------------------
PUBLIC rawrxd_is_finite_f32
rawrxd_is_finite_f32 PROC
    test    rdx, rdx
    jz      Lfin_ok
    xor     r10, r10
Lfin_loop:
    cmp     r10, rdx
    jae     Lfin_ok
    mov     eax, DWORD PTR [rcx+r10*4]
    and     eax, 7F800000h
    cmp     eax, 7F800000h
    je      Lfin_bad
    inc     r10
    jmp     Lfin_loop
Lfin_bad:
    xor     eax, eax
    ret
Lfin_ok:
    mov     eax, 1
    ret
rawrxd_is_finite_f32 ENDP

END