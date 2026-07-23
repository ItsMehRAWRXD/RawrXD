; ============================================================================
; RawrXD Tensor Operations - Pure x64 MASM Implementation
; Zero dependencies, hand-optimized tensor math for transformer inference
; ============================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

; ============================================================================
; Constants
; ============================================================================
CACHE_LINE_SIZE     EQU 64
FLOAT_SIZE          EQU 4
TENSOR_TYPE_F32     EQU 0
TENSOR_TYPE_F16     EQU 1

; ============================================================================
; Data Section
; ============================================================================
.DATA
ALIGN 16

; 256MB tensor arena
g_TensorArena       BYTE 268435456 DUP(0)  ; 256 * 1024 * 1024
g_TensorArenaUsed   QWORD 0
g_TensorArenaLock   QWORD 0

; Constants
exp_one             DD 1.0
exp_half            DD 0.5
exp_sixth           DD 0.16666667
exp_24th            DD 0.04166667
exp_min             DD -10.0
exp_max             DD 10.0

; ============================================================================
; Code Section
; ============================================================================
.CODE

; Arena allocation
ArenaAlloc PROC FRAME
    .endprolog
    add rcx, 15
    and rcx, NOT 15
    mov r8, rcx
alloc_loop:
    mov rax, g_TensorArenaUsed
    mov rdx, rax
    add rdx, r8
    cmp rdx, 268435456
    ja alloc_failed
    lock cmpxchg g_TensorArenaUsed, rdx
    jne alloc_loop
    lea rax, g_TensorArena
    add rax, [g_TensorArenaUsed]
    sub rax, r8
    ret
alloc_failed:
    xor rax, rax
    ret
ArenaAlloc ENDP

; 1D tensor creation
TensorNew1D PROC FRAME
    .endprolog
    push rbx
    push rdi
    mov ebx, ecx
    mov r8, rdx
    mov rax, r8
    shl rax, 2
    mov r9, rax
    add rax, 48
    mov rcx, rax
    call ArenaAlloc
    test rax, rax
    jz tensor_fail
    mov rdi, rax
    mov DWORD PTR [rdi + 0], ebx
    mov QWORD PTR [rdi + 4], r8
    mov QWORD PTR [rdi + 12], 1
    mov QWORD PTR [rdi + 20], 1
    mov QWORD PTR [rdi + 28], 1
    lea rax, [rdi + 48]
    mov QWORD PTR [rdi + 36], rax
    mov rcx, r9
    xor eax, eax
    mov r8, rdi
    mov rdi, QWORD PTR [rdi + 36]
    rep stosb
    mov rax, r8
    pop rdi
    pop rbx
    ret
tensor_fail:
    xor rax, rax
    pop rdi
    pop rbx
    ret
TensorNew1D ENDP

; 2D tensor creation
TensorNew2D PROC FRAME
    .endprolog
    push rbx
    push rdi
    mov ebx, ecx
    mov r9, rdx
    mov r10, r8
    mov rax, r9
    imul rax, r10
    shl rax, 2
    mov r11, rax
    add rax, 48
    mov rcx, rax
    call ArenaAlloc
    test rax, rax
    jz tensor2d_fail
    mov rdi, rax
    mov DWORD PTR [rdi + 0], ebx
    mov QWORD PTR [rdi + 4], r9
    mov QWORD PTR [rdi + 12], r10
    mov QWORD PTR [rdi + 20], 1
    mov QWORD PTR [rdi + 28], 1
    lea rax, [rdi + 48]
    mov QWORD PTR [rdi + 36], rax
    mov rcx, r11
    xor eax, eax
    mov r8, rdi
    mov rdi, QWORD PTR [rdi + 36]
    rep stosb
    mov rax, r8
    pop rdi
    pop rbx
    ret
tensor2d_fail:
    xor rax, rax
    pop rdi
    pop rbx
    ret
TensorNew2D ENDP

; Matrix multiplication C[M,N] = A[M,K] @ B[K,N]
MatMulF32 PROC FRAME
    .endprolog
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r10, QWORD PTR [rsp + 64]
    mov r11, QWORD PTR [rsp + 72]
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov r15, r9
    xor rbx, rbx
m_loop:
    cmp rbx, r15
    jae m_done
    xor rax, rax
n_loop:
    cmp rax, r10
    jae n_done
    xorps xmm0, xmm0
    xor rcx, rcx
k_loop:
    cmp rcx, r11
    jae k_done
    mov rdx, rbx
    imul rdx, r11
    add rdx, rcx
    movss xmm1, DWORD PTR [r12 + rdx * 4]
    mov rdx, rcx
    imul rdx, r10
    add rdx, rax
    movss xmm2, DWORD PTR [r13 + rdx * 4]
    mulss xmm1, xmm2
    addss xmm0, xmm1
    inc rcx
    jmp k_loop
k_done:
    mov rdx, rbx
    imul rdx, r10
    add rdx, rax
    movss DWORD PTR [r14 + rdx * 4], xmm0
    inc rax
    jmp n_loop
n_done:
    inc rbx
    jmp m_loop
m_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
MatMulF32 ENDP

; Softmax
SoftmaxF32 PROC FRAME
    .endprolog
    push rbx
    push r12
    mov r12, rcx
    mov rbx, rdx
    movss xmm0, DWORD PTR [r12]
    mov rcx, 1
max_loop:
    cmp rcx, rbx
    jae max_done
    movss xmm1, DWORD PTR [r12 + rcx * 4]
    maxss xmm0, xmm1
    inc rcx
    jmp max_loop
max_done:
    xorps xmm1, xmm1
    xor rcx, rcx
exp_loop:
    cmp rcx, rbx
    jae exp_done
    movss xmm2, DWORD PTR [r12 + rcx * 4]
    subss xmm2, xmm0
    ; exp approximation
    movss xmm3, xmm2
    movss xmm4, DWORD PTR [exp_min]
    maxss xmm3, xmm4
    movss xmm4, DWORD PTR [exp_max]
    minss xmm3, xmm4
    movss xmm5, DWORD PTR [exp_one]
    movss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, DWORD PTR [exp_half]
    addss xmm5, xmm6
    movss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, DWORD PTR [exp_sixth]
    addss xmm5, xmm6
    movss DWORD PTR [r12 + rcx * 4], xmm5
    addss xmm1, xmm5
    inc rcx
    jmp exp_loop
exp_done:
    xor rcx, rcx
norm_loop:
    cmp rcx, rbx
    jae norm_done
    movss xmm2, DWORD PTR [r12 + rcx * 4]
    divss xmm2, xmm1
    movss DWORD PTR [r12 + rcx * 4], xmm2
    inc rcx
    jmp norm_loop
norm_done:
    pop r12
    pop rbx
    ret
SoftmaxF32 ENDP

; RMSNorm
RMSNormF32 PROC FRAME
    .endprolog
    push rbx
    push r12
    push r13
    mov r12, rcx
    mov r13, rdx
    mov rbx, r8
    movss xmm3, DWORD PTR [r9]
    xorps xmm0, xmm0
    xor rcx, rcx
sum_loop:
    cmp rcx, rbx
    jae sum_done
    movss xmm1, DWORD PTR [r12 + rcx * 4]
    mulss xmm1, xmm1
    addss xmm0, xmm1
    inc rcx
    jmp sum_loop
sum_done:
    cvtsi2ss xmm1, ebx
    divss xmm0, xmm1
    addss xmm0, xmm3
    sqrtss xmm0, xmm0
    xor rcx, rcx
norm_loop:
    cmp rcx, rbx
    jae norm_done
    movss xmm1, DWORD PTR [r12 + rcx * 4]
    divss xmm1, xmm0
    test r13, r13
    jz no_weight
    movss xmm2, DWORD PTR [r13 + rcx * 4]
    mulss xmm1, xmm2
no_weight:
    movss DWORD PTR [r12 + rcx * 4], xmm1
    inc rcx
    jmp norm_loop
norm_done:
    pop r13
    pop r12
    pop rbx
    ret
RMSNormF32 ENDP

; SiLU activation
SiLUF32 PROC FRAME
    .endprolog
    push rbx
    mov rbx, rdx
    xor rdx, rdx
silu_loop:
    cmp rdx, rbx
    jae silu_done
    movss xmm0, DWORD PTR [rcx + rdx * 4]
    movss xmm1, xmm0
    xorps xmm2, xmm2
    subss xmm2, xmm1
    movss xmm0, xmm2
    ; exp
    movss xmm3, xmm0
    movss xmm4, DWORD PTR [exp_min]
    maxss xmm3, xmm4
    movss xmm4, DWORD PTR [exp_max]
    minss xmm3, xmm4
    movss xmm5, DWORD PTR [exp_one]
    movss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, DWORD PTR [exp_half]
    addss xmm5, xmm6
    movss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, xmm3
    mulss xmm6, DWORD PTR [exp_sixth]
    addss xmm5, xmm6
    movss xmm2, xmm5
    movss xmm1, DWORD PTR [exp_one]
    addss xmm1, xmm2
    movss xmm0, DWORD PTR [exp_one]
    divss xmm0, xmm1
    movss xmm1, DWORD PTR [rcx + rdx * 4]
    mulss xmm0, xmm1
    movss DWORD PTR [rcx + rdx * 4], xmm0
    inc rdx
    jmp silu_loop
silu_done:
    pop rbx
    ret
SiLUF32 ENDP

; Exports
PUBLIC ArenaAlloc
PUBLIC TensorNew1D
PUBLIC TensorNew2D
PUBLIC MatMulF32
PUBLIC SoftmaxF32
PUBLIC RMSNormF32
PUBLIC SiLUF32
PUBLIC g_TensorArena
PUBLIC g_TensorArenaUsed

END
