; =============================================================================
; swiglu.asm - SwiGLU Feed-Forward Network
; =============================================================================
; Implements: SwiGLU(x) = (SiLU(x * W_gate) * (x * W_up)) * W_down
;
; This is the standard FFN for LLaMA-2/3, Mistral, Qwen2, and Phi-3.
;
; Dimensions:
;   x:       [batch, hidden_dim]
;   W_gate:  [hidden_dim, ffn_dim]
;   W_up:    [hidden_dim, ffn_dim]
;   W_down:  [ffn_dim, hidden_dim]
;   output:  [batch, hidden_dim]
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; SwiGLU workspace
align 64
g_SwiGLUWorkspace      DQ 0
g_SwiGLUWorkspaceSize  DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_SwiGLU_Init - Allocate SwiGLU workspace
;
; Parameters:
;   RCX = QWORD hidden_dim
;   RDX = QWORD ffn_dim
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_SwiGLU_Init PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    ; Need 2 * ffn_dim floats for gate and up projections
    mov rax, rdx
    shl rax, 3                      ; * 8 (2 * 4 bytes)
    add rax, 63
    and rax, -64

    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [g_SwiGLUWorkspace], rax
    mov QWORD PTR [g_SwiGLUWorkspaceSize], rcx

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_SwiGLU_Init ENDP

; =============================================================================
; RawrXD_SwiGLU - Compute SwiGLU FFN
;
; Parameters:
;   RCX = float* x        - Input (hidden_dim)
;   RDX = float* out      - Output (hidden_dim)
;   R8  = float* W_gate   - Gate weights (hidden_dim, ffn_dim)
;   R9  = float* W_up     - Up weights (hidden_dim, ffn_dim)
;   [RBP+48] = float* W_down - Down weights (ffn_dim, hidden_dim)
;   [RBP+56] = QWORD hidden_dim
;   [RBP+64] = QWORD ffn_dim
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_SwiGLU PROC FRAME
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
    sub rsp, 96
    .allocstack 96
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error
    test r9, r9
    jz @@error

    mov rsi, rcx                    ; x
    mov rdi, rdx                    ; out
    mov rbx, r8                     ; W_gate
    mov r12, r9                     ; W_up
    mov r13, QWORD PTR [rbp + 48]  ; W_down
    mov r14, QWORD PTR [rbp + 56]  ; hidden_dim
    mov r15, QWORD PTR [rbp + 64]  ; ffn_dim

    ; Workspace pointers
    mov rax, QWORD PTR [g_SwiGLUWorkspace]
    mov QWORD PTR [rbp - 8], rax   ; gate_out (ffn_dim)
    mov QWORD PTR [rbp - 16], rax  ; up_out (ffn_dim)
    add QWORD PTR [rbp - 16], r15
    shl QWORD PTR [rbp - 16], 2   ; up_out = workspace + ffn_dim * 4

    ; =========================================================================
    ; Step 1: gate = x * W_gate  (hidden_dim -> ffn_dim)
    ; =========================================================================
    mov rcx, rsi
    mov rdx, rbx
    mov r8, QWORD PTR [rbp - 8]
    mov r9, 1                       ; batch = 1
    sub rsp, 48
    mov QWORD PTR [rsp + 32], r15  ; N = ffn_dim
    mov QWORD PTR [rsp + 40], r14  ; K = hidden_dim
    mov QWORD PTR [rsp + 48], 0    ; No bias
    call RawrXD_MatMul_F32
    add rsp, 48
    test rax, rax
    jnz @@error

    ; =========================================================================
    ; Step 2: up = x * W_up  (hidden_dim -> ffn_dim)
    ; =========================================================================
    mov rcx, rsi
    mov rdx, r12
    mov r8, QWORD PTR [rbp - 16]
    mov r9, 1
    sub rsp, 48
    mov QWORD PTR [rsp + 32], r15
    mov QWORD PTR [rsp + 40], r14
    mov QWORD PTR [rsp + 48], 0
    call RawrXD_MatMul_F32
    add rsp, 48
    test rax, rax
    jnz @@error

    ; =========================================================================
    ; Step 3: gate = SiLU(gate)
    ; =========================================================================
    mov rcx, QWORD PTR [rbp - 8]
    mov rdx, r15
    shl rdx, 2                      ; bytes
    call RawrXD_SiLU

    ; =========================================================================
    ; Step 4: gate = gate * up  (element-wise multiply)
    ; =========================================================================
    xor r9, r9

@@mul_loop:
    cmp r9, r15
    jge @@step5

    mov rax, r9
    shl rax, 2
    mov rcx, QWORD PTR [rbp - 8]
    mov rdx, QWORD PTR [rbp - 16]
    movss xmm0, DWORD PTR [rcx + rax]
    mulss xmm0, DWORD PTR [rdx + rax]
    movss DWORD PTR [rcx + rax], xmm0

    inc r9
    jmp @@mul_loop

@@step5:
    ; =========================================================================
    ; Step 5: out = gate * W_down  (ffn_dim -> hidden_dim)
    ; =========================================================================
    mov rcx, QWORD PTR [rbp - 8]
    mov rdx, r13
    mov r8, rdi
    mov r9, 1
    sub rsp, 48
    mov QWORD PTR [rsp + 32], r14  ; N = hidden_dim
    mov QWORD PTR [rsp + 40], r15  ; K = ffn_dim
    mov QWORD PTR [rsp + 48], 0    ; No bias
    call RawrXD_MatMul_F32
    add rsp, 48
    test rax, rax
    jnz @@error

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_SwiGLU ENDP

END
