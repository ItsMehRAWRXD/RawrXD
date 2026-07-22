; ============================================================================
; sovereign_q4k_gemv.asm - Q4_K_M GEMV Kernels
; Two entry points:
;   Sovereign_Q4K_GEMV_AVX2    - row-major y[r] = sum_k W[r,k] * x[k]
;   Sovereign_Q4K_GEMV_AVX2_T  - column-strided y[r] = sum_k W[k,r] * x[k]
; ============================================================================

.code

; Q4_K_M block: 32 scales(fp16)=64B, 32 mins(fp16)=64B, 256 weights(4-bit)=128B
; Total: 256 bytes per 256 weights

; ============================================================================
; Sovereign_Q4K_GEMV_AVX2
;   void f(const void* q4, const float* x, float* y, uint32 num_blocks, uint32 rows)
; ============================================================================
Sovereign_Q4K_GEMV_AVX2 PROC FRAME
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    .endprolog

    mov r12, rcx            ; q4_weights
    mov r13, rdx            ; input
    mov r14, r8             ; output
    mov r15d, r9d           ; num_blocks
    mov ebx, [rsp+96]       ; rows

    test ebx, ebx
    jz done_rm

    xor r10d, r10d

row_loop_rm:
    vxorps ymm0, ymm0, ymm0
    xor r11d, r11d
    mov rsi, r12

block_loop_rm:
    xor rdi, rdi
group_loop_rm:
    mov rdx, rdi
    shl rdx, 1
    movzx eax, word ptr [rsi + rdx]
    vmovd xmm1, eax
    vcvtph2ps xmm1, xmm1
    vbroadcastss ymm1, xmm1
    movzx eax, word ptr [rsi + rdx + 64]
    vmovd xmm2, eax
    vcvtph2ps xmm2, xmm2
    vbroadcastss ymm2, xmm2
    mov rdx, rdi
    shr rdx, 1
    movzx eax, byte ptr [rsi + rdx + 128]
    test rdi, 1
    jz even_g_rm
    shr eax, 4
    jmp ud_rm
even_g_rm:
    and eax, 0Fh
ud_rm:
    vcvtsi2ss xmm3, xmm3, eax
    vbroadcastss ymm3, xmm3
    vmulps ymm3, ymm3, ymm1
    vaddps ymm3, ymm3, ymm2
    mov rdx, r11
    shl rdx, 8
    mov r8, rdi
    shl r8, 3
    add rdx, r8
    vmovups ymm4, [r13 + rdx * 4]
    vfmadd231ps ymm0, ymm3, ymm4
    inc rdi
    cmp rdi, 32
    jl group_loop_rm
    inc r11d
    add rsi, 256
    cmp r11d, r15d
    jl block_loop_rm
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    movss dword ptr [r14 + r10 * 4], xmm0
    inc r10d
    add r12, 256
    cmp r10d, ebx
    jl row_loop_rm

done_rm:
    vzeroupper
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

Sovereign_Q4K_GEMV_AVX2 ENDP

; ============================================================================
; Sovereign_Q4K_GEMV_AVX2_T  - column-strided
;   y[r] = sum_k W[k, r] * x[k]  for r in [0, rows)
; W is row-major: W[k, r] at byte offset (k * num_blocks * 256) + (r * 256)
; So row_stride_bytes = 256 (each column starts 256 bytes after the previous)
; Wait - that's not right for general strides. Let me parameterize.
; Actually the real case is: W is [K, N] stored row-major. y[n] = sum_k W[k,n] * x[k].
; Each "column" of W spans K rows, each row is 256-aligned for the Q4K block.
; For Q4K_M with 256 elements per block, the column stride between consecutive
; outputs n and n+1 within a row is 256/8 = 32 BYTES (4 bits per weight).
; And the row stride (advancing k) is num_blocks_per_row * 256 bytes.
; ============================================================================
Sovereign_Q4K_GEMV_AVX2_T PROC FRAME
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    sub rsp, 16             ; space for row_stride
    .endprolog

    mov r12, rcx            ; q4_weights
    mov r13, rdx            ; input
    mov r14, r8             ; output
    mov r15d, r9d           ; num_blocks (= K / 256)
    mov ebx, [rsp+96+16]   ; rows (= N)
    mov eax, [rsp+104+16]  ; row_stride_bytes
    mov [rsp], rax

    test ebx, ebx
    jz done_t

    xor r10d, r10d

row_loop_t:
    vxorps ymm0, ymm0, ymm0
    xor r11d, r11d
    mov rsi, r12

block_loop_t:
    xor rdi, rdi
group_loop_t:
    mov rdx, rdi
    shl rdx, 1
    movzx eax, word ptr [rsi + rdx]
    vmovd xmm1, eax
    vcvtph2ps xmm1, xmm1
    vbroadcastss ymm1, xmm1
    movzx eax, word ptr [rsi + rdx + 64]
    vmovd xmm2, eax
    vcvtph2ps xmm2, xmm2
    vbroadcastss ymm2, xmm2
    mov rdx, rdi
    shr rdx, 1
    movzx eax, byte ptr [rsi + rdx + 128]
    test rdi, 1
    jz even_g_t
    shr eax, 4
    jmp ud_t
even_g_t:
    and eax, 0Fh
ud_t:
    vcvtsi2ss xmm3, xmm3, eax
    vbroadcastss ymm3, xmm3
    vmulps ymm3, ymm3, ymm1
    vaddps ymm3, ymm3, ymm2
    mov rdx, r11
    shl rdx, 8
    mov r8, rdi
    shl r8, 3
    add rdx, r8
    vmovups ymm4, [r13 + rdx * 4]
    vfmadd231ps ymm0, ymm3, ymm4
    inc rdi
    cmp rdi, 32
    jl group_loop_t

    inc r11d
    add rsi, 256            ; next block along the column
    cmp r11d, r15d
    jl block_loop_t

    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    movss dword ptr [r14 + r10 * 4], xmm0

    mov rax, [rsp]          ; row_stride_bytes
    add r12, rax            ; advance to next column's first row
    inc r10d
    cmp r10d, ebx
    jl row_loop_t

done_t:
    vzeroupper
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

Sovereign_Q4K_GEMV_AVX2_T ENDP

END
