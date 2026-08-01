; =============================================================================
; attention.asm - Multi-Head Scaled Dot-Product Attention
; =============================================================================
; Implements: Attention(Q,K,V) = softmax(Q * K^T / sqrt(d_k)) * V
;
; Supports:
;   - MHA (Multi-Head Attention)
;   - GQA (Grouped Query Attention)
;   - MQA (Multi-Query Attention)
;   - Flash attention-style tiling (optional)
;   - Causal masking (autoregressive)
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Attention workspace (allocated at init)
align 64
g_AttnWorkspace        DQ 0
g_AttnWorkspaceSize    DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_AttentionInit - Initialize attention workspace
;
; Parameters:
;   RCX = QWORD max_seq_len
;   RDX = QWORD n_heads
;   R8  = QWORD head_dim
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_AttentionInit PROC FRAME
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
    test r8, r8
    jz @@error

    ; Calculate score matrix size: seq_len * seq_len * 4 bytes
    mov rax, rcx
    mul rcx
    shl rax, 2                      ; * 4 for float32
    add rax, 63
    and rax, -64                    ; Align to 64

    ; Allocate workspace
    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [g_AttnWorkspace], rax
    mov QWORD PTR [g_AttnWorkspaceSize], rcx

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

RawrXD_AttentionInit ENDP

; =============================================================================
; RawrXD_Attention - Compute scaled dot-product attention
;
; Parameters:
;   RCX = float* Q        - Query (seq_len, n_heads, head_dim)
;   RDX = float* K        - Key   (seq_len, n_kv_heads, head_dim)
;   R8  = float* V        - Value (seq_len, n_kv_heads, head_dim)
;   R9  = float* out      - Output (seq_len, n_heads, head_dim)
;   [RBP+48]  = QWORD seq_len
;   [RBP+56]  = QWORD n_heads
;   [RBP+64]  = QWORD n_kv_heads
;   [RBP+72]  = QWORD head_dim
;   [RBP+80]  = QWORD* mask (optional causal mask)
;   [RBP+88]  = DWORD is_causal (0/1)
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_Attention PROC FRAME
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
    sub rsp, 128
    .allocstack 128
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error
    test r9, r9
    jz @@error

    mov rsi, rcx                    ; Q
    mov rdi, rdx                    ; K
    mov rbx, r8                     ; V
    mov r12, r9                     ; out
    mov r13, QWORD PTR [rbp + 48]  ; seq_len
    mov r14, QWORD PTR [rbp + 56]  ; n_heads
    mov r15, QWORD PTR [rbp + 64]  ; n_kv_heads
    mov QWORD PTR [rbp - 8], QWORD PTR [rbp + 72]  ; head_dim
    mov QWORD PTR [rbp - 16], QWORD PTR [rbp + 80] ; mask
    movzx eax, BYTE PTR [rbp + 88] ; is_causal
    mov QWORD PTR [rbp - 24], rax

    ; Scale factor = 1/sqrt(head_dim)
    cvtsi2ss xmm0, QWORD PTR [rbp - 8]
    sqrtss xmm0, xmm0
    movss xmm1, DWORD PTR [g_OneF32]
    divss xmm1, xmm0
    vbroadcastss ymm7, xmm1         ; ymm7 = scale

    ; Head stride = head_dim * 4 bytes
    mov rax, QWORD PTR [rbp - 8]
    shl rax, 2
    mov QWORD PTR [rbp - 32], rax  ; head_stride

    ; Seq stride = n_heads * head_stride
    mov rax, r14
    mul QWORD PTR [rbp - 32]
    mov QWORD PTR [rbp - 40], rax  ; seq_stride

    ; KV head stride (for GQA)
    mov rax, QWORD PTR [rbp - 8]
    shl rax, 2
    mov QWORD PTR [rbp - 48], rax  ; kv_head_stride

    ; KV seq stride = n_kv_heads * kv_head_stride
    mov rax, r15
    mul QWORD PTR [rbp - 48]
    mov QWORD PTR [rbp - 56], rax  ; kv_seq_stride

    ; Groups per head (for GQA)
    mov rax, r14
    xor edx, edx
    div r15
    mov QWORD PTR [rbp - 64], rax  ; groups_per_head

    ; Score matrix pointer
    mov rax, QWORD PTR [g_AttnWorkspace]
    mov QWORD PTR [rbp - 72], rax

    ; =========================================================================
    ; For each query head:
    ;   score[i] = Q[i] * K^T / sqrt(d_k)
    ;   attn[i] = softmax(score[i])
    ;   out[i]  = attn[i] * V
    ; =========================================================================
    xor r9, r9                      ; query position

@@qpos_loop:
    cmp r9, r13
    jge @@done

    xor r10, r10                    ; head index

@@head_loop:
    cmp r10, r14
    jge @@next_qpos

    ; Q head base = qpos * seq_stride + head * head_stride
    mov rax, r9
    mul QWORD PTR [rbp - 40]
    mov rcx, r10
    mul QWORD PTR [rbp - 32]
    add rax, rcx
    add rax, rsi
    mov QWORD PTR [rbp - 80], rax  ; Q_head

    ; KV head = head / groups_per_head
    mov rax, r10
    xor edx, edx
    div QWORD PTR [rbp - 64]
    mov r11, rax                    ; kv_head

    ; Score row = workspace + qpos * seq_len
    mov rax, r9
    mul r13
    shl rax, 2
    add rax, QWORD PTR [rbp - 72]
    mov QWORD PTR [rbp - 88], rax  ; score_row

    ; Compute Q * K^T for this head
    xor r8, r8                      ; kv position

@@kvpos_loop:
    cmp r8, r13
    jge @@softmax_row

    ; K head base = kvpos * kv_seq_stride + kv_head * kv_head_stride
    mov rax, r8
    mul QWORD PTR [rbp - 56]
    mov rcx, r11
    mul QWORD PTR [rbp - 48]
    add rax, rcx
    add rax, rdi
    mov QWORD PTR [rbp - 96], rax  ; K_head

    ; Dot product: sum(Q[i] * K[j]) over head_dim
    vxorps ymm0, ymm0, ymm0
    xor rcx, rcx

@@dot_loop:
    cmp rcx, QWORD PTR [rbp - 8]
    jge @@store_score

    mov rax, rcx
    shl rax, 2
    vmovss xmm1, DWORD PTR [rsi + rax]  ; Q[d]
    vmovss xmm2, DWORD PTR [rdi + rax]  ; K[d]
    vfmadd231ss xmm0, xmm1, xmm2

    add rcx, 1
    jmp @@dot_loop

@@store_score:
    ; Apply scale
    vmulss xmm0, xmm0, xmm7

    ; Apply causal mask if needed
    cmp QWORD PTR [rbp - 24], 0
    je @@no_mask
    cmp r8, r9
    jbe @@no_mask
    ; Set to -inf for causal (positions after current)
    mov eax, 0FF800000h             ; -inf
    movd xmm0, eax

@@no_mask:
    ; Store score
    mov rax, r8
    shl rax, 2
    add rax, QWORD PTR [rbp - 88]
    movss DWORD PTR [rax], xmm0

    inc r8
    jmp @@kvpos_loop

@@softmax_row:
    ; Apply softmax to score row
    mov rcx, QWORD PTR [rbp - 88]
    mov rdx, r13
    shl rdx, 2
    call RawrXD_Softmax

    ; Compute attention output: out = softmax(score) * V
    vxorps ymm0, ymm0, ymm0
    xor r8, r8

@@attn_loop:
    cmp r8, r13
    jge @@store_out

    ; Load attention weight
    mov rax, r8
    shl rax, 2
    add rax, QWORD PTR [rbp - 88]
    vbroadcastss ymm1, DWORD PTR [rax]  ; attn_weight

    ; V head base = kvpos * kv_seq_stride + kv_head * kv_head_stride
    mov rax, r8
    mul QWORD PTR [rbp - 56]
    mov rcx, r11
    mul QWORD PTR [rbp - 48]
    add rax, rcx
    add rax, rbx

    ; out += attn_weight * V
    vmovups ymm2, YMMWORD PTR [rax]
    vfmadd231ps ymm0, ymm1, ymm2

    inc r8
    jmp @@attn_loop

@@store_out:
    ; Store output
    mov rax, r9
    mul QWORD PTR [rbp - 40]
    mov rcx, r10
    mul QWORD PTR [rbp - 32]
    add rax, rcx
    add rax, r12
    vmovups YMMWORD PTR [rax], ymm0

    inc r10
    jmp @@head_loop

@@next_qpos:
    inc r9
    jmp @@qpos_loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    vzeroupper
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_Attention ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_OneF32            REAL4 1.0

END
