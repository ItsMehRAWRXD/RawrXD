; ============================================================================
; RawrXD QuantKB Engine -- Pure x64 MASM64
; 2-Bit Non-Uniform Bucket-Mapped Block Quantizer
; Target: 5.33x compression for 1000x VRAM oversubscription streaming
; ============================================================================

PUBLIC CompressBlock64_MASM
PUBLIC DecompressBlock64_MASM

.const
ALIGN 16
__three_f32  REAL4 3.0

.code

; ============================================================================
; CompressBlock64_MASM
;   RCX = const float* src (64 floats, 256 bytes)
;   RDX = QuantKB2Bit* dst (24 bytes output)
; ============================================================================
CompressBlock64_MASM PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    .endprolog

    mov     rsi, rcx
    mov     rdi, rdx

    ; 1. Find min and max across 64 floats
    movss   xmm0, DWORD PTR [rsi]
    movss   xmm1, xmm0
    mov     r8, 1
minmax_loop:
    movss   xmm2, DWORD PTR [rsi + r8*4]
    minss   xmm0, xmm2
    maxss   xmm1, xmm2
    inc     r8
    cmp     r8, 63
    jle     minmax_loop

    ; 2. Compute step = (max - min) / 3.0
    movss   xmm3, xmm1
    subss   xmm3, xmm0
    lea     rax, __three_f32
    movss   xmm8, DWORD PTR [rax]
    divss   xmm3, xmm8

    movss   xmm4, xmm0          ; c0 = min
    movss   xmm5, xmm0
    addss   xmm5, xmm3          ; c1
    movss   xmm6, xmm5
    addss   xmm6, xmm3          ; c2
    movss   xmm7, xmm1          ; c3 = max

    ; Store centroids to stack
    sub     rsp, 32
    movss   DWORD PTR [rsp],    xmm4
    movss   DWORD PTR [rsp+4],  xmm5
    movss   DWORD PTR [rsp+8],  xmm6
    movss   DWORD PTR [rsp+12], xmm7

    ; 3. Convert centroids to FP16 and store in header
    mov     r15, rsp
    mov     r14, rdi
    mov     ecx, 4
    xor     r13, r13

centroid_convert_loop:
    movss   xmm0, DWORD PTR [r15 + r13*4]
    movd    eax, xmm0
    mov     edx, eax
    and     edx, 007FFFFFh      ; mantissa

    mov     r8d, eax
    shr     r8d, 31             ; sign bit
    shl     r8d, 15

    mov     r9d, eax
    shr     r9d, 23
    and     r9d, 0FFh           ; exponent
    sub     r9d, 127
    add     r9d, 15
    cmp     r9d, 31
    jge     cvt_inf
    cmp     r9d, 0
    jle     cvt_zero
    shl     r9d, 10

    mov     r10d, edx
    shr     r10d, 13
    and     r10d, 03FFh

    or      r8d, r9d
    or      r8d, r10d
    jmp     cvt_store
cvt_inf:
    or      r8d, 7C00h
    jmp     cvt_store
cvt_zero:
    jmp     cvt_store
cvt_store:
    mov     WORD PTR [r14 + r13*2], r8w
    inc     r13
    dec     ecx
    jnz     centroid_convert_loop

    ; 4. Clear packed bit fields
    mov     QWORD PTR [rdi+8], 0
    mov     QWORD PTR [rdi+16], 0

    ; 5. Quantize 64 elements
    xor     r9, r9
    xor     r12, r12
    xor     r13, r13

quant_loop:
    movss   xmm0, DWORD PTR [rsi + r9*4]

    ; distance to c0
    movss   xmm1, xmm0
    subss   xmm1, DWORD PTR [rsp]
    movd    eax, xmm1
    and     eax, 7FFFFFFFh
    movd    xmm1, eax

    ; distance to c1
    movss   xmm2, xmm0
    subss   xmm2, DWORD PTR [rsp+4]
    movd    eax, xmm2
    and     eax, 7FFFFFFFh
    movd    xmm2, eax

    ; distance to c2
    movss   xmm3, xmm0
    subss   xmm3, DWORD PTR [rsp+8]
    movd    eax, xmm3
    and     eax, 7FFFFFFFh
    movd    xmm3, eax

    ; distance to c3
    movss   xmm4, xmm0
    subss   xmm4, DWORD PTR [rsp+12]
    movd    eax, xmm4
    and     eax, 7FFFFFFFh
    movd    xmm4, eax

    ; find minimum distance index
    xor     rax, rax
    movss   xmm5, xmm1

    comiss  xmm2, xmm5
    jae     check_c2
    mov     rax, 1
    movss   xmm5, xmm2
check_c2:
    comiss  xmm3, xmm5
    jae     check_c3
    mov     rax, 2
    movss   xmm5, xmm3
check_c3:
    comiss  xmm4, xmm5
    jae     store_bits
    mov     rax, 3

store_bits:
    cmp     r9, 32
    jae     pack_upper
    mov     rcx, r9
    shl     rcx, 1
    shl     rax, cl
    or      r12, rax
    jmp     next_elem
pack_upper:
    mov     rcx, r9
    sub     rcx, 32
    shl     rcx, 1
    shl     rax, cl
    or      r13, rax
next_elem:
    inc     r9
    cmp     r9, 64
    jl      quant_loop

    mov     QWORD PTR [rdi+8], r12
    mov     QWORD PTR [rdi+16], r13

    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
CompressBlock64_MASM ENDP

; ============================================================================
; DecompressBlock64_MASM
;   RCX = const QuantKB2Bit* src (24 bytes)
;   RDX = float* dst (256 bytes, 64 floats)
; ============================================================================
DecompressBlock64_MASM PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    .endprolog

    mov     rsi, rcx
    mov     rdi, rdx
    sub     rsp, 32

    ; Convert 4 FP16 centroids to FP32
    xor     rbx, rbx
centroid_dequant_loop:
    movzx   eax, WORD PTR [rsi + rbx*2]

    mov     r8d, eax
    and     r8d, 07C00h
    shr     r8d, 10             ; FP16 exponent

    mov     r9d, eax
    and     r9d, 003FFh         ; FP16 mantissa

    mov     r10d, eax
    and     r10d, 08000h
    shl     r10d, 16            ; FP32 sign bit

    cmp     r8d, 0
    je      dq_zero
    cmp     r8d, 31
    je      dq_inf

    sub     r8d, 15
    add     r8d, 127
    shl     r8d, 23             ; FP32 exponent

    mov     r11d, r9d
    shl     r11d, 13            ; FP32 mantissa

    or      r10d, r8d
    or      r10d, r11d
    jmp     dq_store
dq_zero:
    jmp     dq_store
dq_inf:
    mov     r10d, 07F800000h
    jmp     dq_store
dq_store:
    mov     DWORD PTR [rsp + rbx*4], r10d
    inc     rbx
    cmp     rbx, 4
    jl      centroid_dequant_loop

    ; Unpack 64 elements
    xor     r8, r8
decompress_loop:
    mov     rax, r8
    shr     rax, 5
    mov     rdx, r8
    and     rdx, 31
    shl     rdx, 1
    mov     r9, QWORD PTR [rsi + 8 + rax*8]
    mov     rcx, rdx
    shr     r9, cl
    and     r9, 3
    movss   xmm0, DWORD PTR [rsp + r9*4]
    movss   DWORD PTR [rdi + r8*4], xmm0
    inc     r8
    cmp     r8, 64
    jl      decompress_loop

    add     rsp, 32
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DecompressBlock64_MASM ENDP

END
