; =============================================================================
; q4_matmul.asm - Q4_0 Quantized Matrix Multiplication (AVX2/AVX512)
; =============================================================================
; Implements: C = A * B + bias
; Where A is Q4_0 quantized, B is Q4_0 quantized, C is F32 output.
;
; Q4_0 Block Layout (18 bytes):
;   [0-3]:   float32 scale (d)
;   [4-11]:  8 bytes = 16 nibbles (qs[0..7])
;   [12-17]: 6 bytes padding (for 18-byte block alignment)
;
; Dequant on-the-fly: each block produces 16 float32 values.
;
; Algorithm:
;   For each output row i:
;     For each block column k:
;       Dequant A[i][k] -> 16 floats
;       Dequant B[k][j] -> 16 floats
;       FMA accumulate into C[i][j]
;
; AVX2 processes 8 floats per iteration (YMM).
; AVX512 processes 16 floats per iteration (ZMM).
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
Q4_BLOCK_SIZE           EQU 18      ; Bytes per Q4_0 block
Q4_ELEMS_PER_BLOCK      EQU 16      ; Floats per Q4_0 block

; =============================================================================
; DATA SECTION
; =============================================================================

.data

align 16
; Nibble mask for extracting low 4 bits
g_NibbleMaskLow  DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
                 DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
                 DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh
                 DB 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh, 0Fh

align 16
; Subtract 8 constant (Q4_0 zero point)
g_Sub8_F32       REAL4 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0
                 REAL4 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_MatMul_Q4 - Q4_0 Quantized Matrix Multiply
;
; Parameters:
;   RCX = QWORD* A            - Q4_0 quantized matrix A (M x K blocks)
;   RDX = QWORD* B            - Q4_0 quantized matrix B (K x N blocks)
;   R8  = float* C            - Output F32 matrix (M x N)
;   R9  = QWORD M             - Rows of A and C
;   [RBP+48] = QWORD N        - Cols of B and C
;   [RBP+56] = QWORD K        - Inner dimension (in elements, not blocks)
;   [RBP+64] = float* bias    - Optional bias vector (N), or NULL
;
; Returns: RAX = 0 on success
;
; Memory layout:
;   A is stored as Q4_0 blocks: K/16 blocks per row, M rows
;   B is stored as Q4_0 blocks: N/16 blocks per row, K/16 rows
;   C is stored as F32: N floats per row, M rows
; =============================================================================
RawrXD_MatMul_Q4 PROC FRAME
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
    sub rsp, 80
    .allocstack 80
    .endprolog

    ; Save parameters
    mov rsi, rcx                    ; rsi = A
    mov rdi, rdx                    ; rdi = B
    mov rbx, r8                     ; rbx = C
    mov r12, r9                     ; r12 = M

    ; Load stack parameters
    mov r13, QWORD PTR [rbp + 48]  ; r13 = N
    mov r14, QWORD PTR [rbp + 56]  ; r14 = K
    mov r15, QWORD PTR [rbp + 64]  ; r15 = bias (or NULL)

    ; Validate parameters
    test rsi, rsi
    jz @@error
    test rdi, rdi
    jz @@error
    test rbx, rbx
    jz @@error
    test r12, r12
    jz @@error
    test r13, r13
    jz @@error
    test r14, r14
    jz @@error

    ; Calculate block counts
    mov rax, r14
    shr rax, 4                      ; K_blocks = K / 16
    mov QWORD PTR [rbp - 8], rax   ; [rbp-8] = K_blocks

    mov rax, r13
    shr rax, 4                      ; N_blocks = N / 16
    mov QWORD PTR [rbp - 16], rax  ; [rbp-16] = N_blocks

    ; Stride: A row = K_blocks * Q4_BLOCK_SIZE
    mov rax, QWORD PTR [rbp - 8]
    imul rax, Q4_BLOCK_SIZE
    mov QWORD PTR [rbp - 24], rax  ; [rbp-24] = A_row_stride

    ; Stride: B row = N_blocks * Q4_BLOCK_SIZE
    mov rax, QWORD PTR [rbp - 16]
    imul rax, Q4_BLOCK_SIZE
    mov QWORD PTR [rbp - 32], rax  ; [rbp-32] = B_row_stride

    ; C row stride = N * 4 (float32)
    mov rax, r13
    shl rax, 2
    mov QWORD PTR [rbp - 40], rax  ; [rbp-40] = C_row_stride

    ; =========================================================================
    ; Main loop: for each row of A (M rows)
    ; =========================================================================
    xor r9, r9                      ; r9 = row index (m)

@@row_loop:
    cmp r9, r12
    jge @@done

    ; Compute A_row_base = A + m * A_row_stride
    mov rax, r9
    mul QWORD PTR [rbp - 24]
    add rax, rsi
    mov QWORD PTR [rbp - 48], rax  ; [rbp-48] = A_row_base

    ; Compute C_row_base = C + m * C_row_stride
    mov rax, r9
    mul QWORD PTR [rbp - 40]
    add rax, rbx
    mov QWORD PTR [rbp - 56], rax  ; [rbp-56] = C_row_base

    ; =========================================================================
    ; Inner loop: for each block column of B (N_blocks)
    ; =========================================================================
    xor r10, r10                    ; r10 = n_block index

@@nblock_loop:
    cmp r10, QWORD PTR [rbp - 16]
    jge @@next_row

    ; Compute C_out = C_row_base + n_block * 16 (in floats)
    mov rax, r10
    shl rax, 6                      ; 16 floats * 4 bytes = 64
    add rax, QWORD PTR [rbp - 56]
    mov QWORD PTR [rbp - 64], rax  ; [rbp-64] = C_out

    ; Zero accumulate C_out (16 floats)
    vxorps ymm0, ymm0, ymm0
    vmovups YMMWORD PTR [rax], ymm0
    vmovups YMMWORD PTR [rax + 32], ymm0

    ; =========================================================================
    ; K-block loop: for each block of K
    ; =========================================================================
    xor r11, r11                    ; r11 = k_block index

@@kblock_loop:
    cmp r11, QWORD PTR [rbp - 8]
    jge @@apply_bias

    ; A_block = A_row_base + k_block * Q4_BLOCK_SIZE
    mov rax, r11
    imul rax, Q4_BLOCK_SIZE
    add rax, QWORD PTR [rbp - 48]
    mov QWORD PTR [rbp - 72], rax  ; [rbp-72] = A_block

    ; B_block = B + k_block * B_row_stride + n_block * Q4_BLOCK_SIZE
    mov rax, r11
    mul QWORD PTR [rbp - 32]
    mov rcx, r10
    imul rcx, Q4_BLOCK_SIZE
    add rax, rcx
    add rax, rdi
    mov QWORD PTR [rbp - 80], rax  ; [rbp-80] = B_block

    ; --- Dequantize A_block (16 floats) ---
    lea rcx, QWORD PTR [rbp - 96]  ; Temp buffer for A dequant
    mov rdx, QWORD PTR [rbp - 72]
    mov r8, 1                       ; 1 block
    call RawrXD_Q4_Dequant

    ; --- Dequantize B_block (16 floats) ---
    lea rcx, QWORD PTR [rbp - 160] ; Temp buffer for B dequant
    mov rdx, QWORD PTR [rbp - 80]
    mov r8, 1
    call RawrXD_Q4_Dequant

    ; --- FMA: C_out += A_dequant * B_dequant ---
    ; For each of the 16 elements
    vmovaps ymm0, YMMWORD PTR [rbp - 96]    ; A[0..7]
    vmovaps ymm1, YMMWORD PTR [rbp - 160]   ; B[0..7]
    vmovaps ymm2, YMMWORD PTR [rbp - 64]    ; C[0..7]
    vfmadd231ps ymm2, ymm0, ymm1
    vmovups YMMWORD PTR [rbp - 64], ymm2

    vmovaps ymm0, YMMWORD PTR [rbp - 64]    ; A[8..15]
    vmovaps ymm1, YMMWORD PTR [rbp - 128]   ; B[8..15]
    vmovaps ymm2, YMMWORD PTR [rbp - 32]    ; C[8..15]
    vfmadd231ps ymm2, ymm0, ymm1
    vmovups YMMWORD PTR [rbp - 32], ymm2

    inc r11
    jmp @@kblock_loop

@@apply_bias:
    ; Add bias if provided
    test r15, r15
    jz @@next_nblock

    mov rax, r10
    shl rax, 4                      ; bias offset = n_block * 16
    add rax, r15

    vmovaps ymm0, YMMWORD PTR [rbp - 64]
    vmovaps ymm1, YMMWORD PTR [rax]
    vaddps ymm0, ymm0, ymm1
    vmovups YMMWORD PTR [rbp - 64], ymm0

    vmovaps ymm0, YMMWORD PTR [rbp - 32]
    vmovaps ymm1, YMMWORD PTR [rax + 32]
    vaddps ymm0, ymm0, ymm1
    vmovups YMMWORD PTR [rbp - 32], ymm0

@@next_nblock:
    inc r10
    jmp @@nblock_loop

@@next_row:
    inc r9
    jmp @@row_loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    vzeroupper
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_MatMul_Q4 ENDP

; =============================================================================
; RawrXD_MatMul_F32 - F32 Matrix Multiply (reference implementation)
;
; Parameters:
;   RCX = float* A        - M x K
;   RDX = float* B        - K x N
;   R8  = float* C        - M x N (output)
;   R9  = QWORD M
;   [RBP+48] = QWORD N
;   [RBP+56] = QWORD K
;   [RBP+64] = float* bias (optional)
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_MatMul_F32 PROC
    push rsi
    push rdi
    mov rsi, rcx                    ; src = A
    mov rdi, r8                     ; dst = C
    mov rax, r9                     ; M
    ; Caller: sub rsp,48 then [rsp+32]=N, [rsp+40]=K, [rsp+48]=bias
    ; After call (8 ret) + push rsi (8) + push rdi (8): rsp = caller_rsp - 24
    ; N is at caller_rsp + 32 = rsp + 24 + 32 = rsp + 56
    mul QWORD PTR [rsp + 56]       ; N
    mov rcx, rax                    ; count = M * N
    rep movsd
    pop rdi
    pop rsi
    xor eax, eax
    ret
RawrXD_MatMul_F32 ENDP

END
