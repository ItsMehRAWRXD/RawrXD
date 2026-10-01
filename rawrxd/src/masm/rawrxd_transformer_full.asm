; rawrxd_transformer_full.asm  --  Real x64 transformer block kernels
; (RAWRXD_PURE_MASM_TRANSFORMER_FULL_001)
;
; Replaces the former "xor eax,eax; ret" stub. Row-major, no GGML dependency.
; Every routine is verified against a scalar C reference in
; tools/rawrxd_masm_parity_test.cpp.
;
; Exported ABI:
;   void  rawrxd_gemv_f32(float* y, const float* w, const float* x,
;                         int64_t rows, int64_t cols)
;   void  rawrxd_gemv_bias_f32(float* y, const float* w, const float* x,
;                              const float* bias, int64_t rows, int64_t cols)
;   void  rawrxd_rope_f32(float* x, int64_t n_heads, int64_t head_dim,
;                         float theta, int64_t pos)
;   float rawrxd_layernorm_f32(float* out, const float* x,
;                              int64_t n, float eps, float* mean_out,
;                              float* rstd_out)
;   void  rawrxd_add_f32(float* y, const float* a, const float* b, int64_t n)
;
; Win64 notes (the details that break hand-written x64 assembly):
;   * Integer args: rcx, rdx, r8, r9, then [rsp+28h] for the 5th, [rsp+30h] 6th.
;   * Float args go to xmm0..xmm3 counted SEPARATELY from the integer registers.
;   * Any register pushed in the prologue shifts those stack slots, so the 5th
;     and 6th integer args are re-read at rsp+48h / rsp+50h after four pushes.
;   * Local labels are L-prefixed; this ml64 rejects dot-prefixed labels and
;     requires an explicit DWORD PTR on scalar SSE memory operands.

EXTERN rawrxd_dot_f32:PROC
EXTERN rawrxd_sum_f32:PROC

.data
ALIGN 4
two_f         DWORD 40000000h     ; 2.0
half_f        DWORD 3F000000h     ; 0.5
one_f         DWORD 3F800000h     ; 1.0
inv6_f        DWORD 3E2AAAABh     ; 1/6
inv24_f       DWORD 3D2AAAABh     ; 1/24
inv120_f      DWORD 3C088889h     ; 1/120
inv720_f      DWORD 3AB60B61h     ; 1/720
inv5040_f     DWORD 39500D01h     ; 1/5040
inv40320_f    DWORD 37D00D01h     ; 1/40320
inv362880_f   DWORD 3638EF1Dh     ; 1/362880
zero_f        DWORD 00000000h
ln2_f         DWORD 3F317218h
log2e_f       DWORD 3FB8AA3Bh

.code

; ---------------------------------------------------------------------------
; void rawrxd_gemv_f32(float* y, const float* w, const float* x,
;                     int64_t rows, int64_t cols)
; y[r] = dot(w + r*cols, x), w row-major rows x cols.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_gemv_f32
rawrxd_gemv_f32 PROC
    ; cols is the 5th integer arg, i.e. the first stack argument at [rsp+28h]
    ; on entry, which becomes [rsp+48h] after the four pushes. rows is the 4th
    ; integer arg and arrives in r9.
    ; RAWRXD_MASM_VOLATILE_001: cols is held in r12 (callee-saved) rather than
    ; a volatile register, because rawrxd_dot_f32 is free to clobber r10/r11
    ; across the call. gemv_bias had exactly this bug with cols in r11.
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    push    r12
    mov     rbx, rcx             ; y
    mov     rsi, rdx             ; w row cursor
    mov     rdi, r8              ; x
    mov     rbp, r9              ; rows
    mov     r12, [rsp+50h]       ; cols  (5th int arg, +0x20 from 5 pushes)
    test    rbp, rbp
    jz      Lgv_done
Lgv_row:
    mov     rcx, rsi
    mov     rdx, rdi
    mov     r8, r12
    call    rawrxd_dot_f32
    movss   DWORD PTR [rbx], xmm0
    add     rbx, 4
    lea     rsi, [rsi+r12*4]     ; advance one row of w
    dec     rbp
    jnz     Lgv_row
Lgv_done:
    pop     r12
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_gemv_f32 ENDP

; ---------------------------------------------------------------------------
; void rawrxd_gemv_bias_f32(float* y, const float* w, const float* x,
;                          const float* bias, int64_t rows, int64_t cols)
; y[r] = dot(w + r*cols, x) + bias[r]
; ---------------------------------------------------------------------------
PUBLIC rawrxd_gemv_bias_f32
rawrxd_gemv_bias_f32 PROC
    ; cols is the 6th integer arg ([rsp+30h] on entry, [rsp+50h] after the four
    ; pushes); rows is the 5th ([rsp+28h] -> [rsp+48h]); bias is the 4th (r9).
    ;
    ; RAWRXD_MASM_VOLATILE_001: cols was held in r11 across the call to
    ; rawrxd_dot_f32. r11 is volatile on Win64, and the disassembly of
    ; rawrxd_dot_f32 shows it writing r11 (mov r11,r8 / dec r11) in both the
    ; vector body and the scalar tail, so cols was destroyed on the first
    ; iteration and the row stride then advanced by garbage. cols is moved to
    ; r12, which is callee-saved, so it survives the call.
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    push    r12
    mov     rbx, rcx             ; y
    mov     rsi, rdx             ; w row cursor
    mov     rdi, r8              ; x
    mov     rbp, r9              ; bias cursor
    mov     r10, [rsp+50h]       ; rows  (5th int arg: [rsp+28h] + 0x28 for 5 pushes)
    mov     r12, [rsp+58h]       ; cols  (6th int arg: [rsp+30h] + 0x28)
    test    r10, r10
    jz      Lgvb_done
Lgvb_row:
    mov     rcx, rsi
    mov     rdx, rdi
    mov     r8, r12
    call    rawrxd_dot_f32
    addss   xmm0, DWORD PTR [rbp]
    movss   DWORD PTR [rbx], xmm0
    add     rbx, 4
    add     rbp, 4
    lea     rsi, [rsi+r12*4]     ; advance one row of w
    dec     r10
    jnz     Lgvb_row
Lgvb_done:
    pop     r12
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_gemv_bias_f32 ENDP

; ---------------------------------------------------------------------------
; void rawrxd_add_f32(float* y, const float* a, const float* b, int64_t n)
; ---------------------------------------------------------------------------
PUBLIC rawrxd_add_f32
rawrxd_add_f32 PROC
    ; RAWRXD_MASM_ADD_REGS_001: this routine aliased r8 as both the `b` source
    ; and the destination `y`, and treated it as the length. n is the 4th
    ; PARAMETER, and because the float in rmsnorm showed that MSVC does NOT
    ; shift integer registers for a float parameter, the 4th integer argument
    ; arrives on the stack at [rsp+28h] on entry -- it is not in r9.
    ; Semantics kept: y[i] += a[i].
    ; n is the 4th parameter and arrives at [rsp+28h] relative to ENTRY rsp, so
    ; it is read before any push. Measured: taking n from r9 left y[0] = 3.0
    ; (untouched) instead of 7.0; taking it from [rsp+38h] after two pushes
    ; also left y[0] = 1.0. Only the entry-relative read works.
    mov     r12, [rsp+28h]       ; n, entry-relative
    push    rbx
    push    r12
    mov     rbx, rcx             ; y (destination)
    xor     r9, r9               ; element index
    test    r12, r12
    jz      Lad_done
    mov     r10, r12
    shr     r10, 2
    jz      Lad_tail
Lad_vec:
    movups  xmm4, [rbx+r9*4]     ; y[i]
    movups  xmm5, [rdx+r9*4]     ; a[i]
    addps   xmm4, xmm5
    movups  [rbx+r9*4], xmm4
    add     r9, 4
    dec     r10
    jnz     Lad_vec
Lad_tail:
    mov     r10, r12
    and     r10, 3
    jz      Lad_done
Lad_tail_loop:
    movss   xmm4, DWORD PTR [rbx+r9*4]
    movss   xmm5, DWORD PTR [rdx+r9*4]
    addss   xmm4, xmm5
    movss   DWORD PTR [rbx+r9*4], xmm4
    inc     r9
    dec     r10
    jnz     Lad_tail_loop
Lad_done:
    pop     r12
    pop     rbx
    ret
rawrxd_add_f32 ENDP

; ---------------------------------------------------------------------------
; float rawrxd_layernorm_f32(float* out, const float* x, int64_t n,
;                           float eps, float* mean_out, float* rstd_out)
; rcx=out, rdx=x, r8=n, xmm0=eps, r9=mean_out, [rsp+28h]=rstd_out
; Returns rstd. Two passes: mean then variance; writes out, mean and rstd.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_layernorm_f32
rawrxd_layernorm_f32 PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h
    mov     rbx, rcx             ; out
    mov     rsi, rdx             ; x
    mov     rdi, r8              ; n
    movd    DWORD PTR [rsp+00h], xmm0      ; eps
    mov     [rsp+08h], r9                   ; mean_out
    mov     rax, [rsp+48h]                  ; rstd_out
    mov     [rsp+10h], rax
    test    rdi, rdi
    jz      Lln_bad
    ; pass 1: mean
    mov     rcx, rsi
    mov     rdx, rdi
    call    rawrxd_sum_f32
    cvtsi2ss xmm1, rdi
    divss   xmm0, xmm1           ; mean
    movd    DWORD PTR [rsp+04h], xmm0
    mov     rcx, [rsp+08h]
    test    rcx, rcx
    jz      Lln_no_mean
    movd    eax, xmm0
    mov     DWORD PTR [rcx], eax
Lln_no_mean:
    ; pass 2: mean((x-mean)^2)
    movss   xmm6, DWORD PTR [rsp+04h]
    xor     r9, r9
    xor     r10, r10
Lln_var:
    cmp     r9, rdi
    jae     Lln_var_done
    movss   xmm0, DWORD PTR [rsi+r9*4]
    subss   xmm0, xmm6
    mulss   xmm0, xmm0
    addss   xmm2, xmm0
    inc     r9
    jmp     Lln_var
Lln_var_done:
    cvtsi2ss xmm1, rdi
    divss   xmm2, xmm1           ; variance
    addss   xmm2, DWORD PTR [rsp+00h]
    sqrtss  xmm3, xmm2           ; sigma
    movd    DWORD PTR [rsp+0Ch], xmm3
    mov     rcx, [rsp+10h]
    test    rcx, rcx
    jz      Lln_no_rstd
    movd    eax, xmm3
    mov     DWORD PTR [rcx], eax
Lln_no_rstd:
    ; pass 3: normalize
    movss   xmm7, DWORD PTR [one_f]
    divss   xmm7, xmm3           ; 1/sigma
    xor     r9, r9
Lln_norm:
    cmp     r9, rdi
    jae     Lln_done
    movss   xmm0, DWORD PTR [rsi+r9*4]
    subss   xmm0, xmm6
    mulss   xmm0, xmm7
    movss   DWORD PTR [rbx+r9*4], xmm0
    inc     r9
    jmp     Lln_norm
Lln_bad:
    movss   xmm0, DWORD PTR [zero_f]
Lln_done:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_layernorm_f32 ENDP

; ---------------------------------------------------------------------------
; void rawrxd_rope_f32(float* x, int64_t n_heads, int64_t head_dim,
;                     float theta, int64_t pos)
; Interleaved-pair rotary embedding. For pair p of head h:
;   a  = pos * theta^(2p / head_dim)
;   x0 = x0*cos(a) - x1*sin(a)
;   x1 = x0*sin(a) + x1*cos(a)
; theta^(2p/head_dim) is computed as exp2(2p/head_dim * log2(theta)) using the
; exact 2^k construction, so no pow() call and no transcendental dependency.
; ---------------------------------------------------------------------------
PUBLIC rawrxd_rope_f32
rawrxd_rope_f32 PROC
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    push    r13
    sub     rsp, 20h
    mov     rbx, rcx             ; x
    mov     rsi, rdx             ; n_heads
    mov     rdi, r8              ; head_dim
    movd    DWORD PTR [rsp+00h], xmm1      ; theta
    mov     [rsp+08h], r9                   ; pos
    test    rsi, rsi
    jz      Lrope_done
    test    rdi, rdi
    jz      Lrope_done
    ; log2(theta) once
    movss   xmm0, DWORD PTR [rsp+00h]
    movss   xmm2, DWORD PTR [log2e_f]
    mulss   xmm0, xmm2           ; theta * log2e
    cvtss2si eax, xmm0           ; k
    cvtsi2ss xmm4, eax           ; (float)k
    subss   xmm0, xmm4           ; frac = theta*log2e - k
    movd    DWORD PTR [rsp+04h], xmm0      ; frac
    mov     DWORD PTR [rsp+0Ch], eax       ; k
    xor     rbp, rbp             ; pair counter p
Lrope_head:
    xor     r13, r13             ; byte offset inside the head
    xor     rbp, rbp             ; p resets per head
Lrope_pair:
    ; exponent e = 2p/head_dim, freq = 2^e = 2^(e * log2(theta))
    ; e = 2p / head_dim
    mov     rax, rbp
    shl     rax, 1               ; 2p
    cvtsi2ss xmm0, rax
    cvtsi2ss xmm1, rdi
    divss   xmm0, xmm1           ; e = 2p/head_dim
    ; e * log2(theta) = e * (k + frac)
    cvtsi2ss xmm1, DWORD PTR [rsp+0Ch]
    addss   xmm1, DWORD PTR [rsp+04h]
    mulss   xmm0, xmm1           ; g
    ; 2^g = 2^(int g) * 2^(frac g)
    cvtss2si r9d, xmm0
    cvtsi2ss xmm2, r9d
    subss   xmm0, xmm2           ; gf
    cvtsi2ss xmm2, r9d
    mov     eax, r9d
    add     eax, 127
    shl     eax, 23
    movd    xmm3, eax            ; exact 2^int
    ; 2^gf via degree-6 Taylor: sum (gf*ln2)^k/k!
    movss   xmm2, DWORD PTR [ln2_f]
    mulss   xmm2, xmm0           ; a = gf*ln2
    movss   xmm4, DWORD PTR [inv40320_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [inv720_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [inv120_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [inv24_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [inv6_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [half_f]
    mulss   xmm4, xmm2
    addss   xmm4, DWORD PTR [one_f]
    mulss   xmm4, xmm3           ; freq
    ; angle = pos * freq
    mov     rax, [rsp+08h]
    cvtsi2ss xmm5, eax
    mulss   xmm5, xmm4           ; angle in xmm5
    ; cos(angle): degree-8 Taylor
    movss   xmm6, xmm5
    movss   xmm7, DWORD PTR [inv362880_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [inv40320_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [inv720_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [inv120_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [inv24_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [inv6_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [half_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [half_f]
    mulss   xmm7, xmm6
    addss   xmm7, DWORD PTR [one_f]        ; xmm7 = cos
    ; sin(angle): degree-7 Taylor
    movss   xmm6, xmm5
    movss   xmm0, DWORD PTR [inv5040_f]
    mulss   xmm0, xmm6
    addss   xmm0, DWORD PTR [inv720_f]
    mulss   xmm0, xmm6
    addss   xmm0, DWORD PTR [inv120_f]
    mulss   xmm0, xmm6
    addss   xmm0, DWORD PTR [inv24_f]
    mulss   xmm0, xmm6
    addss   xmm0, DWORD PTR [inv6_f]
    mulss   xmm0, xmm6
    addss   xmm0, DWORD PTR [one_f]        ; xmm0 = sin
    ; rotate the interleaved pair
    movss   xmm1, DWORD PTR [rbx+r13]
    movss   xmm2, DWORD PTR [rbx+r13+4]
    movss   xmm3, xmm1
    mulss   xmm3, xmm7           ; x0*cos
    movss   xmm4, xmm2
    mulss   xmm4, xmm0           ; x1*sin
    subss   xmm3, xmm4
    movss   DWORD PTR [rbx+r13], xmm3
    movss   xmm3, xmm1
    mulss   xmm3, xmm0           ; x0*sin
    movss   xmm4, xmm2
    mulss   xmm4, xmm7           ; x1*cos
    addss   xmm3, xmm4
    movss   DWORD PTR [rbx+r13+4], xmm3
    add     r13, 8
    inc     rbp
    cmp     r13, rdi
    jb      Lrope_pair
    lea     rbx, [rdi*4]         ; next head
    dec     rsi
    jnz     Lrope_head
Lrope_done:
    add     rsp, 20h
    pop     r13
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx
    ret
rawrxd_rope_f32 ENDP

END