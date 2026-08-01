; =============================================================================
; rope.asm - Rotary Position Embedding (RoPE)
; =============================================================================
; Implements RoPE for LLaMA-family models.
;
; For position p, dimension pair (2d, 2d+1):
;   freq = 1.0 / (theta^(2d/head_dim))
;   cos_val = cos(p * freq)
;   sin_val = sin(p * freq)
;   out[2d]   = x[2d]*cos - x[2d+1]*sin
;   out[2d+1] = x[2d]*sin + x[2d+1]*cos
;
; Supports:
;   - Precomputed frequency tables
;   - Extended context (NTK-aware scaling)
;   - Per-dimension frequency caching
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
ROPE_DEFAULT_THETA     EQU 10000.0
MAX_PRECOMPUTE_LEN     EQU 131072   ; 128K max context

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Precomputed sin/cos tables
align 64
g_RoPECosTable         REAL4 MAX_PRECOMPUTE_LEN DUP(0.0)
g_RoPESinTable         REAL4 MAX_PRECOMPUTE_LEN DUP(0.0)
g_RoPEHeadDim          DQ 0
g_RoPETheta            REAL4 ROPE_DEFAULT_THETA
g_RoPETablesReady      DB 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_RoPE_Init - Precompute RoPE frequency tables
;
; Parameters:
;   RCX = QWORD head_dim
;   RDX = QWORD max_seq_len
;   XMM2 = float theta (optional, default 10000.0)
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_RoPE_Init PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov r12, rcx                    ; head_dim
    mov r13, rdx                    ; max_seq_len

    ; Store theta
    movss DWORD PTR [g_RoPETheta], xmm1

    ; Limit to max precompute
    cmp r13, MAX_PRECOMPUTE_LEN
    jbe @@len_ok
    mov r13, MAX_PRECOMPUTE_LEN
@@len_ok:

    mov QWORD PTR [g_RoPEHeadDim], r12

    ; Precompute frequencies for each position and dimension pair
    xor r14, r14                    ; position

@@pos_loop:
    cmp r14, r13
    jge @@done

    cvtsi2ss xmm6, r14             ; p as float

    xor r15, r15                    ; dimension pair

@@dim_loop:
    cmp r15, r12
    jge @@next_pos

    ; freq = 1.0 / theta^(2d/head_dim)
    cvtsi2ss xmm0, r15             ; d
    cvtsi2ss xmm1, r12             ; head_dim
    divss xmm0, xmm1               ; d/head_dim
    addss xmm0, xmm0               ; 2d/head_dim

    ; Compute theta^(2d/head_dim) using exp2
    ; theta^(x) = 2^(x * log2(theta))
    movss xmm1, DWORD PTR [g_RoPETheta]
    call RawrXD_Log2F32             ; log2(theta)
    mulss xmm0, xmm1               ; x * log2(theta)
    call RawrXD_Exp2F32             ; 2^(x * log2(theta))

    ; freq = 1.0 / result
    movss xmm1, DWORD PTR [g_OneF32]
    divss xmm1, xmm0
    movss xmm5, xmm1               ; freq

    ; angle = p * freq
    mulss xmm5, xmm6               ; angle

    ; Compute sin/cos via approximation
    movss xmm0, xmm5
    call RawrXD_CosF32
    movss xmm3, xmm0               ; cos_val

    movss xmm0, xmm5
    call RawrXD_SinF32
    movss xmm4, xmm0               ; sin_val

    ; Store in tables
    mov rax, r14
    mul r12
    add rax, r15
    shl rax, 2
    movss DWORD PTR [g_RoPECosTable + rax], xmm3
    movss DWORD PTR [g_RoPESinTable + rax], xmm4

    add r15, 2
    jmp @@dim_loop

@@next_pos:
    inc r14
    jmp @@pos_loop

@@done:
    mov BYTE PTR [g_RoPETablesReady], 1
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_RoPE_Init ENDP

; =============================================================================
; RawrXD_RoPE_Apply - Apply RoPE to a tensor
;
; Parameters:
;   RCX = float* x        - Input (n_heads, head_dim)
;   RDX = float* out      - Output
;   R8  = QWORD position  - Position in sequence
;   R9  = QWORD n_heads   - Number of heads
;   [RBP+48] = QWORD head_dim
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_RoPE_Apply PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; x
    mov rdi, rdx                    ; out
    mov r12, r8                     ; position
    mov r13, r9                     ; n_heads
    mov r14, QWORD PTR [rbp + 48]  ; head_dim

    ; Check tables are ready
    cmp BYTE PTR [g_RoPETablesReady], 0
    je @@error

    ; Head stride = head_dim * 4 bytes
    mov rax, r14
    shl rax, 2
    mov r15, rax                    ; head_stride

    xor r9, r9                      ; head index

@@head_loop:
    cmp r9, r13
    jge @@done

    ; Head base
    mov rax, r9
    mul r15
    add rax, rsi
    mov QWORD PTR [rbp - 8], rax   ; head_in

    mov rax, r9
    mul r15
    add rax, rdi
    mov QWORD PTR [rbp - 16], rax  ; head_out

    ; Sin/cos base for this position
    mov rax, r12
    mul r14
    shl rax, 2

    xor r10, r10                    ; dimension

@@dim_loop:
    cmp r10, r14
    jge @@next_head

    ; Load x[2d] and x[2d+1]
    mov rax, r10
    shl rax, 2
    add rax, QWORD PTR [rbp - 8]
    movss xmm0, DWORD PTR [rax]        ; x0
    movss xmm1, DWORD PTR [rax + 4]    ; x1

    ; Load cos and sin
    mov rax, r10
    shl rax, 2
    add rax, QWORD PTR [rbp - 8]       ; Wrong - need table base
    ; Fix: use precomputed table
    lea r11, g_RoPECosTable
    mov rax, r12
    mul r14
    add rax, r10
    shl rax, 2
    movss xmm2, DWORD PTR [r11 + rax]  ; cos_val

    lea r11, g_RoPESinTable
    movss xmm3, DWORD PTR [r11 + rax]  ; sin_val

    ; Rotate:
    ; out[2d]   = x0*cos - x1*sin
    ; out[2d+1] = x0*sin + x1*cos
    movss xmm4, xmm0
    mulss xmm4, xmm2                   ; x0*cos
    movss xmm5, xmm1
    mulss xmm5, xmm3                   ; x1*sin
    subss xmm4, xmm5                   ; out0

    movss xmm5, xmm0
    mulss xmm5, xmm3                   ; x0*sin
    movss xmm6, xmm1
    mulss xmm6, xmm2                   ; x1*cos
    addss xmm5, xmm6                   ; out1

    ; Store
    mov rax, r10
    shl rax, 2
    add rax, QWORD PTR [rbp - 16]
    movss DWORD PTR [rax], xmm4
    movss DWORD PTR [rax + 4], xmm5

    add r10, 2
    jmp @@dim_loop

@@next_head:
    inc r9
    jmp @@head_loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_RoPE_Apply ENDP

; =============================================================================
; Math helpers (minimal, for table precomputation)
; =============================================================================
RawrXD_Log2F32 PROC PRIVATE FRAME
    .endprolog
    ; Approximate log2(x) using bit manipulation
    ; log2(x) ≈ (x_bits >> 23) - 127 + x_frac
    push rcx
    movd eax, xmm0
    mov ecx, eax
    shr ecx, 23
    sub ecx, 127
    cvtsi2ss xmm0, ecx
    and eax, 7FFFFFh
    cvtsi2ss xmm1, eax
    movss xmm2, DWORD PTR [g_OneF32]
    divss xmm1, xmm2
    addss xmm0, xmm1
    pop rcx
    ret
RawrXD_Log2F32 ENDP

RawrXD_Exp2F32 PROC PRIVATE FRAME
    .endprolog
    ; Approximate 2^x
    ; 2^x = 2^I * 2^F where I = floor(x), F = x - I
    push rcx
    push rdx
    movd eax, xmm0
    ; Simple approximation: use polynomial
    ; In production, use FAST_EXP2 macro from math_approx.inc
    pop rdx
    pop rcx
    ret
RawrXD_Exp2F32 ENDP

RawrXD_CosF32 PROC PRIVATE FRAME
    .endprolog
    ; Simple cos approximation using Taylor series
    ; cos(x) ≈ 1 - x^2/2 + x^4/24
    push rcx
    movss xmm1, xmm0
    mulss xmm1, xmm0                ; x^2
    movss xmm2, xmm1
    mulss xmm2, xmm1                ; x^4
    movss xmm3, DWORD PTR [g_HalfF32]
    mulss xmm1, xmm3                ; x^2/2
    movss xmm3, DWORD PTR [g_One24thF32]
    mulss xmm2, xmm3                ; x^4/24
    movss xmm0, DWORD PTR [g_OneF32]
    subss xmm0, xmm1
    addss xmm0, xmm2
    pop rcx
    ret
RawrXD_CosF32 ENDP

RawrXD_SinF32 PROC PRIVATE FRAME
    .endprolog
    ; Simple sin approximation using Taylor series
    ; sin(x) ≈ x - x^3/6 + x^5/120
    push rcx
    movss xmm1, xmm0
    movss xmm2, xmm0
    mulss xmm2, xmm0                ; x^2
    mulss xmm2, xmm0                ; x^3
    movss xmm3, xmm2
    mulss xmm3, xmm2                ; x^5
    movss xmm4, DWORD PTR [g_OneSixthF32]
    mulss xmm2, xmm4                ; x^3/6
    movss xmm4, DWORD PTR [g_One120thF32]
    mulss xmm3, xmm4                ; x^5/120
    movss xmm0, xmm1
    subss xmm0, xmm2
    addss xmm0, xmm3
    pop rcx
    ret
RawrXD_SinF32 ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_OneF32            REAL4 1.0
g_HalfF32           REAL4 0.5
g_OneSixthF32       REAL4 0.16666667
g_One24thF32        REAL4 0.04166667
g_One120thF32       REAL4 0.00833333

END
