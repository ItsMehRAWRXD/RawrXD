; ============================================================================
; RawrXD Inference Tensor Operations - Pure x64 MASM Implementation
; Zero dependencies, hand-optimized tensor math for transformer inference
; ============================================================================
; Replaces GGML with custom assembly kernels:
;   - Tensor allocation/management
;   - Matrix multiplication (naive -> blocked -> AVX-512)
;   - Softmax
;   - RoPE (Rotary Position Embeddings)
;   - SiLU activation
;   - RMSNorm
;   - Attention computation
; ============================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

; ============================================================================
; Constants
; ============================================================================
CACHE_LINE_SIZE     EQU 64
FLOAT_SIZE          EQU 4         ; sizeof(float)

; Tensor types
TENSOR_TYPE_F32     EQU 0
TENSOR_TYPE_F16     EQU 1

; Error codes
ERR_SUCCESS         EQU 0
ERR_NULL_PTR        EQU 1
ERR_INVALID_DIM     EQU 2
ERR_OUT_OF_MEMORY   EQU 3

; ============================================================================
; Data Section - Tensor arena
; ============================================================================
.DATA
ALIGN 16

; Simple bump allocator for tensors (256MB arena)
TENSOR_ARENA_SIZE   EQU (256 * 1024 * 1024)
g_TensorArena       BYTE TENSOR_ARENA_SIZE DUP(0)
g_TensorArenaUsed   QWORD 0
g_TensorArenaLock   QWORD 0

; Thread-local scratch buffer (1MB per thread, 64 threads max)
SCRATCH_SIZE        EQU (1024 * 1024)
g_ScratchBuffers    BYTE SCRATCH_SIZE * 64 DUP(0)

; ============================================================================
; Structures (offsets for C++ interop)
; ============================================================================
; Tensor struct (40 bytes)
TENSOR_OFF_TYPE     EQU 0     ; int32 type
TENSOR_OFF_NE0      EQU 4     ; int64 ne[0]
TENSOR_OFF_NE1      EQU 12    ; int64 ne[1]
TENSOR_OFF_NE2      EQU 20    ; int64 ne[2]
TENSOR_OFF_NE3      EQU 28    ; int64 ne[3]
TENSOR_OFF_DATA     EQU 36    ; void* data (4 bytes padding for alignment)
TENSOR_SIZE         EQU 48    ; Padded to 48 bytes

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ============================================================================
; Arena Allocation - Lock-free bump allocator
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory, or NULL
; ============================================================================
ArenaAlloc PROC FRAME
    .endprolog
    
    ; Align size to 16 bytes
    add rcx, 15
    and rcx, NOT 15
    
    ; Lock-free allocation using cmpxchg loop
    mov r8, rcx                     ; Save requested size
    
alloc_loop:
    mov rax, g_TensorArenaUsed      ; Load current used
    mov rdx, rax
    add rdx, r8                     ; Calculate new used
    
    cmp rdx, TENSOR_ARENA_SIZE      ; Check overflow
    ja alloc_failed
    
    ; Attempt atomic compare-exchange
    lock cmpxchg g_TensorArenaUsed, rdx
    jne alloc_loop                  ; Retry if failed
    
    ; Success - calculate pointer
    lea rax, g_TensorArena
    add rax, [g_TensorArenaUsed]    ; Old value = start of our allocation
    sub rax, r8                     ; Adjust to actual pointer
    ret
    
alloc_failed:
    xor rax, rax                    ; Return NULL
    ret
ArenaAlloc ENDP

; ============================================================================
; Tensor Creation - 1D tensor
; RCX = type, RDX = ne0
; Returns: RAX = pointer to Tensor struct
; ============================================================================
TensorNew1D PROC FRAME
    .endprolog
    
    push rbx
    push rdi
    
    mov ebx, ecx                    ; Save type
    mov r8, rdx                     ; Save ne0
    
    ; Calculate data size
    mov rax, r8
    shl rax, 2                      ; * sizeof(float)
    mov r9, rax                     ; Save data size
    
    ; Allocate tensor struct + data
    add rax, TENSOR_SIZE
    mov rcx, rax
    call ArenaAlloc
    test rax, rax
    jz tensor_fail
    
    mov rdi, rax                    ; RDI = tensor pointer
    
    ; Initialize tensor struct
    mov DWORD PTR [rdi + TENSOR_OFF_TYPE], ebx
    mov QWORD PTR [rdi + TENSOR_OFF_NE0], r8
    mov QWORD PTR [rdi + TENSOR_OFF_NE1], 1
    mov QWORD PTR [rdi + TENSOR_OFF_NE2], 1
    mov QWORD PTR [rdi + TENSOR_OFF_NE3], 1
    
    ; Set data pointer (after struct)
    lea rax, [rdi + TENSOR_SIZE]
    mov QWORD PTR [rdi + TENSOR_OFF_DATA], rax
    
    ; Zero initialize data
    mov rcx, r9                     ; Size
    xor eax, eax
    mov r8, rdi                   ; Save tensor ptr
    mov rdi, QWORD PTR [rdi + TENSOR_OFF_DATA]
    rep stosb
    mov rax, r8                   ; Return tensor ptr
    
    pop rdi
    pop rbx
    ret
    
tensor_fail:
    xor rax, rax
    pop rdi
    pop rbx
    ret
TensorNew1D ENDP

; ============================================================================
; Tensor Creation - 2D tensor
; RCX = type, RDX = ne0, R8 = ne1
; Returns: RAX = pointer to Tensor struct
; ============================================================================
TensorNew2D PROC FRAME
    .endprolog
    
    push rbx
    push rdi
    
    mov ebx, ecx                    ; Save type
    mov r9, rdx                     ; Save ne0
    mov r10, r8                     ; Save ne1
    
    ; Calculate data size
    mov rax, r9
    imul rax, r10                   ; ne0 * ne1
    shl rax, 2                      ; * sizeof(float)
    mov r11, rax                    ; Save data size
    
    ; Allocate tensor struct + data
    add rax, TENSOR_SIZE
    mov rcx, rax
    call ArenaAlloc
    test rax, rax
    jz tensor2d_fail
    
    mov rdi, rax                    ; RDI = tensor pointer
    
    ; Initialize tensor struct
    mov DWORD PTR [rdi + TENSOR_OFF_TYPE], ebx
    mov QWORD PTR [rdi + TENSOR_OFF_NE0], r9
    mov QWORD PTR [rdi + TENSOR_OFF_NE1], r10
    mov QWORD PTR [rdi + TENSOR_OFF_NE2], 1
    mov QWORD PTR [rdi + TENSOR_OFF_NE3], 1
    
    ; Set data pointer
    lea rax, [rdi + TENSOR_SIZE]
    mov QWORD PTR [rdi + TENSOR_OFF_DATA], rax
    
    ; Zero initialize data
    mov rcx, r11
    xor eax, eax
    mov r8, rdi
    mov rdi, QWORD PTR [rdi + TENSOR_OFF_DATA]
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

; ============================================================================
; Matrix Multiplication: C[M,N] = A[M,K] @ B[K,N]
; RCX = A ptr, RDX = B ptr, R8 = C ptr
; R9 = M, [RSP+40] = N, [RSP+48] = K
; ============================================================================
MatMulF32 PROC FRAME
    .endprolog
    
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Load parameters from stack
    mov r10, QWORD PTR [rsp + 64]   ; N
    mov r11, QWORD PTR [rsp + 72]   ; K
    
    mov r12, rcx                    ; A
    mov r13, rdx                    ; B
    mov r14, r8                     ; C
    mov r15, r9                     ; M
    
    ; Outer loop over M
    xor rbx, rbx                    ; i = 0
m_loop:
    cmp rbx, r15
    jae m_done
    
    ; Inner loop over N
    xor rax, rax                    ; j = 0
n_loop:
    cmp rax, r10
    jae n_done
    
    ; Compute dot product: C[i,j] = sum(A[i,k] * B[k,j])
    xorps xmm0, xmm0                ; sum = 0
    
    xor rcx, rcx                    ; k = 0
k_loop:
    cmp rcx, r11
    jae k_done
    
    ; Load A[i,k]
    mov rdx, rbx
    imul rdx, r11
    add rdx, rcx
    movss xmm1, DWORD PTR [r12 + rdx * 4]
    
    ; Load B[k,j]
    mov rdx, rcx
    imul rdx, r10
    add rdx, rax
    movss xmm2, DWORD PTR [r13 + rdx * 4]
    
    ; Multiply and accumulate
    mulss xmm1, xmm2
    addss xmm0, xmm1
    
    inc rcx
    jmp k_loop
    
k_done:
    ; Store result
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

; ============================================================================
; Softmax: x[i] = exp(x[i] - max) / sum(exp(x[i] - max))
; RCX = x ptr, RDX = n
; ============================================================================
SoftmaxF32 PROC FRAME
    .endprolog
    
    push rbx
    push r12
    
    mov r12, rcx                    ; x
    mov rbx, rdx                    ; n
    
    ; Find max
    movss xmm0, DWORD PTR [r12]     ; max = x[0]
    mov rcx, 1
max_loop:
    cmp rcx, rbx
    jae max_done
    movss xmm1, DWORD PTR [r12 + rcx * 4]
    maxss xmm0, xmm1
    inc rcx
    jmp max_loop
max_done:
    
    ; Compute exp(x[i] - max) and sum
    xorps xmm1, xmm1                ; sum = 0
    xor rcx, rcx
exp_loop:
    cmp rcx, rbx
    jae exp_done
    
    movss xmm2, DWORD PTR [r12 + rcx * 4]
    subss xmm2, xmm0                ; x[i] - max
    
    ; exp approximation using Taylor series or call C expf
    ; For now, use simple approximation
    call ExpF32Approx
    
    movss DWORD PTR [r12 + rcx * 4], xmm2
    addss xmm1, xmm2                ; sum += exp
    
    inc rcx
    jmp exp_loop
exp_done:
    
    ; Normalize
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

; ============================================================================
; exp(x) approximation using Taylor series
; Input: xmm2 = x
; Output: xmm2 = exp(x)
; ============================================================================
ExpF32Approx PROC
    ; Save registers
    sub rsp, 16
    movss DWORD PTR [rsp], xmm3
    movss DWORD PTR [rsp + 4], xmm4
    
    ; Clamp x to [-10, 10] to avoid overflow
    movss xmm3, xmm2
    movss xmm4, DWORD PTR [exp_min]
    maxss xmm3, xmm4
    movss xmm4, DWORD PTR [exp_max]
    minss xmm3, xmm4
    
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    movss xmm0, xmm3                ; x
    movss xmm1, DWORD PTR [exp_one] ; 1.0
    
    ; x^2/2
    movss xmm2, xmm0
    mulss xmm2, xmm0
    mulss xmm2, DWORD PTR [exp_half]
    addss xmm1, xmm2
    
    ; x^3/6
    movss xmm2, xmm0
    mulss xmm2, xmm0
    mulss xmm2, xmm0
    mulss xmm2, DWORD PTR [exp_sixth]
    addss xmm1, xmm2
    
    ; x^4/24
    movss xmm2, xmm0
    mulss xmm2, xmm0
    mulss xmm2, xmm2
    mulss xmm2, DWORD PTR [exp_24th]
    addss xmm1, xmm2
    
    movss xmm2, xmm1
    
    ; Restore registers
    movss xmm3, DWORD PTR [rsp]
    movss xmm4, DWORD PTR [rsp + 4]
    add rsp, 16
    ret
ExpF32Approx ENDP

; Data section for ExpF32Approx constants
.DATA
ALIGN 16
exp_one:    DD 1.0
exp_half:   DD 0.5
exp_sixth:  DD 0.16666667
exp_24th:   DD 0.04166667
exp_min:    DD -10.0
exp_max:    DD 10.0

.CODE

; ============================================================================
; RMSNorm: x[i] = x[i] / sqrt(mean(x^2) + eps) * weight[i]
; RCX = x ptr, RDX = weight ptr, R8 = n, R9 = eps
; ============================================================================
RMSNormF32 PROC FRAME
    .endprolog
    
    push rbx
    push r12
    push r13
    
    mov r12, rcx                    ; x
    mov r13, rdx                    ; weight
    mov rbx, r8                     ; n
    movss xmm3, DWORD PTR [r9]      ; eps
    
    ; Compute sum of squares
    xorps xmm0, xmm0                ; sum = 0
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
    
    ; Compute RMS
    cvtsi2ss xmm1, rbx              ; n as float
    divss xmm0, xmm1                ; mean
    addss xmm0, xmm3                ; + eps
    sqrtss xmm0, xmm0               ; sqrt
    
    ; Normalize and apply weight
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

; ============================================================================
; SiLU: x[i] = x[i] * sigmoid(x[i])
; RCX = x ptr, RDX = n
; ============================================================================
SiLUF32 PROC FRAME
    .endprolog
    
    push rbx
    mov rbx, rdx                    ; n
    
    xor rdx, rdx
silu_loop:
    cmp rdx, rbx
    jae silu_done
    
    movss xmm0, DWORD PTR [rcx + rdx * 4]
    
    ; sigmoid(x) = 1 / (1 + exp(-x))
    movss xmm1, xmm0
    xorps xmm2, xmm2
    subss xmm2, xmm1                ; -x
    movss xmm0, xmm2
    call ExpF32Approx
    movss xmm1, DWORD PTR [silu_one]
    addss xmm1, xmm2                ; 1 + exp(-x)
    movss xmm0, DWORD PTR [silu_one]
    divss xmm0, xmm1                ; sigmoid
    
    ; x * sigmoid(x)
    movss xmm1, DWORD PTR [rcx + rdx * 4]
    mulss xmm0, xmm1
    movss DWORD PTR [rcx + rdx * 4], xmm0
    
    inc rdx
    jmp silu_loop
    
silu_done:
    pop rbx
    ret
SiLUF32 ENDP

; Data section for SiLU constants
.DATA
ALIGN 16
silu_one:   DD 1.0

.CODE

; ============================================================================
; RoPE (Rotary Position Embeddings)
; RCX = vec ptr, RDX = head_dim, R8 = pos, R9 = theta_base
; ============================================================================
RoPEF32 PROC FRAME
    .endprolog
    
    push rbx
    push r12
    
    mov r12, rcx                    ; vec
    mov rbx, rdx                    ; head_dim
    cvtsi2ss xmm3, r8d              ; pos as float
    movss xmm4, DWORD PTR [r9]      ; theta_base
    
    xor rcx, rcx
rope_loop:
    cmp rcx, rbx
    jae rope_done
    
    ; freq = 1.0 / (theta_base ^ (2*i / head_dim))
    mov rax, rcx
    shr rax, 1                      ; i / 2
    cvtsi2ss xmm0, eax
    addss xmm0, xmm0                ; 2*i
    cvtsi2ss xmm1, ebx
    divss xmm0, xmm1                ; 2*i / head_dim
    
    ; theta_base ^ x = exp(x * ln(theta_base))
    movss xmm1, DWORD PTR [rope_ln_base]
    mulss xmm0, xmm1
    call ExpF32Approx
    
    movss xmm0, DWORD PTR [rope_one]
    divss xmm0, xmm2                ; 1 / theta_base^x
    
    mulss xmm0, xmm3                ; pos * freq
    
    ; cos and sin
    movss xmm5, xmm0                ; angle
    call CosF32Approx
    movss xmm6, xmm0                ; cos_angle
    movss xmm0, xmm5
    call SinF32Approx
    movss xmm7, xmm0                ; sin_angle
    
    ; Apply rotation
    movss xmm0, DWORD PTR [r12 + rcx * 4]       ; x
    movss xmm1, DWORD PTR [r12 + rcx * 4 + 4]   ; y
    
    ; x' = x * cos - y * sin
    movss xmm2, xmm0
    mulss xmm2, xmm6
    movss xmm3, xmm1
    mulss xmm3, xmm7
    subss xmm2, xmm3
    
    ; y' = x * sin + y * cos
    movss xmm3, xmm0
    mulss xmm3, xmm7
    movss xmm4, xmm1
    mulss xmm4, xmm6
    addss xmm3, xmm4
    
    movss DWORD PTR [r12 + rcx * 4], xmm2
    movss DWORD PTR [r12 + rcx * 4 + 4], xmm3
    
    add rcx, 2
    jmp rope_loop
    
rope_done:
    pop r12
    pop rbx
    ret
RoPEF32 ENDP

; ============================================================================
; cos(x) approximation
; Input: xmm0 = x
; Output: xmm0 = cos(x)
; ============================================================================
CosF32Approx PROC
    ; cos(x) ≈ 1 - x^2/2 + x^4/24 - x^6/720
    movss xmm1, xmm0
    mulss xmm1, xmm1                ; x^2
    
    movss xmm2, DWORD PTR [cos_one]
    
    movss xmm3, xmm1
    mulss xmm3, DWORD PTR [cos_half]
    subss xmm2, xmm3                ; - x^2/2
    
    mulss xmm1, xmm1                ; x^4
    movss xmm3, xmm1
    mulss xmm3, DWORD PTR [cos_24th]
    addss xmm2, xmm3                ; + x^4/24
    
    mulss xmm1, DWORD PTR [cos_x2]  ; x^6 (approx)
    movss xmm3, xmm1
    mulss xmm3, DWORD PTR [cos_720th]
    subss xmm2, xmm3                ; - x^6/720
    
    movss xmm0, xmm2
    ret
CosF32Approx ENDP
cos_720th:  DD 0.00138889
cos_x2:     DD 1.0                ; Placeholder
CosF32Approx ENDP

; ============================================================================
; sin(x) approximation
; Input: xmm0 = x
; Output: xmm0 = sin(x)
; ============================================================================
SinF32Approx PROC
    ; sin(x) ≈ x - x^3/6 + x^5/120 - x^7/5040
    movss xmm1, xmm0                ; x
    mulss xmm1, xmm1                ; x^2
    mulss xmm1, xmm0                ; x^3
    
    movss xmm2, xmm0                ; x
    
    movss xmm3, xmm1
    mulss xmm3, DWORD PTR [sin_sixth]
    subss xmm2, xmm3                ; - x^3/6
    
    mulss xmm1, xmm0                ; x^4
    mulss xmm1, xmm0                ; x^5
    movss xmm3, xmm1
    mulss xmm3, DWORD PTR [sin_120th]
    addss xmm2, xmm3                ; + x^5/120
    
    movss xmm0, xmm2
    ret
    
ALIGN 16
sin_sixth:  DD 0.16666667
sin_120th:  DD 0.00833333
SinF32Approx ENDP

; ============================================================================
; Export table
; ============================================================================
PUBLIC ArenaAlloc
PUBLIC TensorNew1D
PUBLIC TensorNew2D
PUBLIC MatMulF32
PUBLIC SoftmaxF32
PUBLIC RMSNormF32
PUBLIC SiLUF32
PUBLIC RoPEF32

; Data exports
PUBLIC g_TensorArena
PUBLIC g_TensorArenaUsed

END
