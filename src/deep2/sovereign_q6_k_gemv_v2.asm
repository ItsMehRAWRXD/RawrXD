; ============================================================================
; sovereign_q6_k_gemv.asm - Q6_K GEMV Kernel (x64 MASM)
; Dependency-free.
;
; ABI:
;   RCX = Q6_K block pointer
;   RDX = float input vector
;   R8  = float output vector
;   R9  = block count (size_t)
;
; Q6_K block = 210 bytes:
;   ql     128 bytes  (low 4 bits of each weight)
;   qh      64 bytes  (high 2 bits of each weight)
;   scales  16 signed bytes
;   d        1 FP16
;
; Layout (sequential, matching GGML reference):
;   Weight i (0..255):
;     qlIdx  = i / 2
;     qhIdx  = i / 4
;     low4   = (ql[qlIdx] >> ((i & 1) * 4)) & 0x0F
;     high2  = (qh[qhIdx] >> ((i & 3) * 2)) & 0x03
;     q      = low4 | (high2 << 4)
;     scale  = scales[(i / 128) * 8 + (i / 16)]
;     value  = d * scale * (q - 32)
;
; First 128 values:  scales[0..7]
; Second 128 values: scales[8..15]
; ============================================================================

OPTION CASEMAP:NONE

.CODE

PUBLIC Deep2_Q6_K_GEMV
PUBLIC sovereign_q6_k_gemv

Deep2_Q6_K_GEMV PROC
sovereign_q6_k_gemv LABEL NEAR

    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Arguments:
    ;   r12 = blocks
    ;   r13 = x
    ;   r14 = out
    ;   r15 = nBlocks

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    mov     r15, r9

    test    r15, r15
    jz      q6k_done

q6k_block_loop:

    ; ------------------------------------------------------------
    ; Load FP16 d (at block + 208) and convert to FP32 in xmm15.
    ; ------------------------------------------------------------
    movzx   eax, word ptr [r12+208]

    ; Extract sign
    mov     ebx, eax
    and     ebx, 8000h
    shl     ebx, 16

    ; Extract exponent
    mov     esi, eax
    shr     esi, 10
    and     esi, 1fh

    ; Extract mantissa
    mov     edi, eax
    and     edi, 03ffh

    test    esi, esi
    jnz     q6k_d_nonzero_exp

    test    edi, edi
    jz      q6k_d_zero

    ; FP16 subnormal
    mov     ecx, edi
    xor     edx, edx
    mov     eax, -14

q6k_d_norm_loop:
    test    ecx, 400h
    jnz     q6k_d_norm_done
    shl     ecx, 1
    dec     eax
    jmp     q6k_d_norm_loop

q6k_d_norm_done:
    and     ecx, 3ffh
    add     eax, 127
    shl     eax, 23
    shl     ecx, 13
    or      eax, ecx
    or      eax, ebx
    movd    xmm15, eax
    jmp     q6k_d_ready

q6k_d_nonzero_exp:
    cmp     esi, 31
    je      q6k_d_inf_nan
    add     esi, 112
    shl     esi, 23
    shl     edi, 13
    mov     eax, esi
    or      eax, edi
    or      eax, ebx
    movd    xmm15, eax
    jmp     q6k_d_ready

q6k_d_inf_nan:
    shl     edi, 13
    mov     eax, 7f800000h
    or      eax, edi
    or      eax, ebx
    movd    xmm15, eax
    jmp     q6k_d_ready

q6k_d_zero:
    mov     eax, ebx
    movd    xmm15, eax

q6k_d_ready:

    ; ------------------------------------------------------------
    ; Accumulator in xmm14.
    ; Process weights i = 0..255 sequentially.
    ; ------------------------------------------------------------
    xorps   xmm14, xmm14
    xor     r10d, r10d              ; i = weight index 0..255

q6k_weight_loop:
    cmp     r10d, 256
    jae     q6k_store_result

    ; --- Compute scale index ---
    ; half = i / 128  (0 or 1)
    ; group = (i % 128) / 16 = (i & 127) / 16
    ; scaleIdx = half * 8 + group
    mov     eax, r10d
    shr     eax, 7                  ; half = i / 128
    shl     eax, 3                  ; half * 8
    mov     ecx, r10d
    and     ecx, 127                ; i % 128
    shr     ecx, 4                  ; group = (i % 128) / 16
    add     eax, ecx                ; scaleIdx = half * 8 + group

    ; Load scale and compute d * scale
    movsx   eax, byte ptr [r12+192+rax]
    cvtsi2ss xmm13, eax
    mulss   xmm13, xmm15            ; xmm13 = d * scale

    ; --- Extract low 4 bits from ql ---
    ; qlIdx = i / 2
    ; shift = (i & 1) * 4
    mov     eax, r10d
    shr     eax, 1                  ; qlIdx = i / 2
    movzx   ebx, byte ptr [r12+rax] ; ebx = ql[qlIdx]
    mov     ecx, r10d
    and     ecx, 1
    shl     ecx, 2                  ; shift = (i & 1) * 4
    shr     ebx, cl
    and     ebx, 0fh                ; ebx = low4

    ; --- Extract high 2 bits from qh ---
    ; qhIdx = i / 4
    ; shift = (i & 3) * 2
    mov     eax, r10d
    shr     eax, 2                  ; qhIdx = i / 4
    movzx   ecx, byte ptr [r12+128+rax] ; ecx = qh[qhIdx]
    mov     edx, r10d
    and     edx, 3
    shl     edx, 1                  ; shift = (i & 3) * 2
    shr     ecx, edx
    and     ecx, 3                  ; ecx = high2
    shl     ecx, 4
    or      ebx, ecx                ; ebx = q = low4 | (high2 << 4)

    ; --- Compute weight value = d * scale * (q - 32) ---
    sub     ebx, 32
    cvtsi2ss xmm0, ebx
    mulss   xmm0, xmm13             ; xmm0 = weight value

    ; --- Multiply by input[i] and accumulate ---
    movss   xmm1, dword ptr [r13+r10*4]
    mulss   xmm0, xmm1
    addss   xmm14, xmm0

    inc     r10d
    jmp     q6k_weight_loop

q6k_store_result:
    movss   dword ptr [r14], xmm14

    ; Advance: block += 210, x += 256, out += 1
    add     r12, 210
    add     r13, 1024               ; 256 floats = 1024 bytes
    add     r14, 4                  ; 1 float = 4 bytes

    dec     r15
    jnz     q6k_block_loop

q6k_done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

Deep2_Q6_K_GEMV ENDP

END
