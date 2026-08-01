; =============================================================================
; kv_cache.asm - RawrXD KV Cache Manager
; =============================================================================
; Manages the key-value cache for autoregressive generation.
; Supports:
;   - Contiguous cache allocation
;   - Append new K,V for each new token
;   - Read cached K,V for attention computation
;   - Cache eviction for long context windows
;   - Optional quantization (Q4_0) for memory efficiency
;
; KV Cache Structure:
;   K_cache: [n_layers, max_seq_len, n_kv_heads, head_dim]
;   V_cache: [n_layers, max_seq_len, n_kv_heads, head_dim]
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; KV Cache context (128 bytes)
align 16
g_KVCache              DB 128 DUP(0)

; Field offsets
KV_CACHE_K_PTR         EQU 0
KV_CACHE_V_PTR         EQU 8
KV_CACHE_MAX_SEQ_LEN   EQU 16
KV_CACHE_CUR_SEQ_LEN   EQU 24
KV_CACHE_N_LAYERS      EQU 32
KV_CACHE_N_KV_HEADS    EQU 40
KV_CACHE_HEAD_DIM      EQU 48
KV_CACHE_LAYER_STRIDE  EQU 56
KV_CACHE_QUANTIZED     EQU 64
KV_CACHE_TOTAL_BYTES   EQU 72

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_KVCacheCreate - Allocate KV cache
;
; Parameters:
;   RCX = QWORD max_seq_len
;   RDX = QWORD n_layers
;   R8  = QWORD n_kv_heads
;   R9  = QWORD head_dim
;   [RBP+48] = DWORD quantized (0=F32, 1=Q4_0)
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_KVCacheCreate PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error
    test r9, r9
    jz @@error

    mov rsi, rcx                    ; max_seq_len
    mov rdi, rdx                    ; n_layers
    mov r12, r8                     ; n_kv_heads
    mov r13, r9                     ; head_dim
    mov r14d, DWORD PTR [rbp + 48] ; quantized

    ; Calculate per-layer cache size
    ; K_cache per layer: max_seq_len * n_kv_heads * head_dim * element_size
    mov rax, rsi
    mul r12
    mul r13
    mov rbx, rax                    ; rbx = elements per layer

    ; Element size: 4 for F32, 18/16 ≈ 1.125 for Q4_0
    cmp r14d, 0
    je @@f32_size
    ; Q4_0: (elements * 18 + 15) / 16
    mov rax, rbx
    mov rcx, 18
    mul rcx
    add rax, 15
    shr rax, 4
    mov rbx, rax
    jmp @@alloc

@@f32_size:
    shl rbx, 2                      ; * 4 bytes

@@alloc:
    ; Total K cache size = per_layer * n_layers
    mov rax, rbx
    mul rdi
    mov r14, rax                    ; r14 = total K bytes

    ; Allocate K cache
    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [g_KVCache + KV_CACHE_K_PTR], rax

    ; Allocate V cache (same size)
    mov rcx, r14
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_k
    mov QWORD PTR [g_KVCache + KV_CACHE_V_PTR], rax

    ; Populate context
    mov QWORD PTR [g_KVCache + KV_CACHE_MAX_SEQ_LEN], rsi
    mov QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN], 0
    mov QWORD PTR [g_KVCache + KV_CACHE_N_LAYERS], rdi
    mov QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS], r12
    mov QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM], r13
    mov QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE], rbx
    mov DWORD PTR [g_KVCache + KV_CACHE_QUANTIZED], r14d
    mov QWORD PTR [g_KVCache + KV_CACHE_TOTAL_BYTES], r14

    xor rax, rax
    jmp @@exit

@@free_k:
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_K_PTR]
    call RawrXD_AlignedFree

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_KVCacheCreate ENDP

; =============================================================================
; RawrXD_KVCacheAppend - Append K,V for a new token
;
; Parameters:
;   RCX = QWORD layer        - Layer index
;   RDX = float* K_input     - Key tensor for this token (n_kv_heads, head_dim)
;   R8  = float* V_input     - Value tensor for this token
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_KVCacheAppend PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; layer
    mov rdi, rdx                    ; K_input
    mov r12, r8                     ; V_input

    ; Check bounds
    mov rax, QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]
    mov rbx, QWORD PTR [g_KVCache + KV_CACHE_MAX_SEQ_LEN]
    cmp rax, rbx
    jge @@error                     ; Cache full

    ; Calculate position in cache
    ; K_cache[layer][pos] = K_base + layer * layer_stride + pos * kv_heads * head_dim * elem_size
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    mov rax, rsi
    mul rcx
    add rax, QWORD PTR [g_KVCache + KV_CACHE_K_PTR]
    mov rdx, QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul rcx
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    mul rcx
    shl rax, 2
    add rax, rdx
    mov rsi, rax                    ; rsi = K_dest

    ; Copy K data
    mov rcx, rdi
    mov rdx, rsi
    mov r8, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    shl r8, 2
    call RawrXD_MemCopy

    ; Same for V
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    mov rax, QWORD PTR [rbp - 8]   ; layer
    mul rcx
    add rax, QWORD PTR [g_KVCache + KV_CACHE_V_PTR]
    mov rdx, QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul rcx
    mov rcx, QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    mul rcx
    shl rax, 2
    add rax, rdx
    mov rsi, rax                    ; rsi = V_dest

    mov rcx, r12
    mov rdx, rsi
    mov r8, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    shl r8, 2
    call RawrXD_MemCopy

    ; Increment sequence length
    inc QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_KVCacheAppend ENDP

; =============================================================================
; RawrXD_KVCacheRead - Read cached K,V for attention
;
; Parameters:
;   RCX = QWORD layer
;   RDX = float* K_out       - Output buffer for K
;   R8  = float* V_out       - Output buffer for V
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_KVCacheRead PROC FRAME
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

    ; Calculate K source pointer
    mov rax, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    mul rcx
    add rax, QWORD PTR [g_KVCache + KV_CACHE_K_PTR]
    mov rsi, rax

    ; Copy K data (entire cache for this layer)
    mov rcx, rsi
    mov rdx, QWORD PTR [rbp + 24]  ; K_out
    mov r8, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    call RawrXD_MemCopy

    ; Same for V
    mov rax, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    mul QWORD PTR [rbp + 16]       ; layer
    add rax, QWORD PTR [g_KVCache + KV_CACHE_V_PTR]
    mov rsi, rax

    mov rcx, rsi
    mov rdx, QWORD PTR [rbp + 32]  ; V_out
    mov r8, QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    call RawrXD_MemCopy

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

RawrXD_KVCacheRead ENDP

; =============================================================================
; RawrXD_KVCacheEvict - Evict oldest tokens from cache
;
; Parameters:
;   RCX = QWORD keep_tokens - Number of tokens to keep
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_KVCacheEvict PROC FRAME
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

    mov rsi, rcx                    ; keep_tokens
    mov rdi, QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]

    ; If keep_tokens >= current length, nothing to do
    cmp rsi, rdi
    jge @@done

    ; Calculate bytes to shift
    mov rax, rdi
    sub rax, rsi                    ; evict_count
    mov rbx, rax

    ; Per-layer: shift remaining tokens to front
    xor r9, r9                      ; layer index

@@layer_loop:
    cmp r9, QWORD PTR [g_KVCache + KV_CACHE_N_LAYERS]
    jge @@done

    ; K cache shift
    mov rax, r9
    mul QWORD PTR [g_KVCache + KV_CACHE_LAYER_STRIDE]
    add rax, QWORD PTR [g_KVCache + KV_CACHE_K_PTR]

    ; Source = base + keep_tokens * token_stride
    mov rcx, rsi
    mov rdx, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul rdx
    mov rdx, QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    mul rdx
    shl rax, 2
    add rax, rcx
    mov rsi, rax                    ; source

    ; Dest = base
    mov rdi, rax
    sub rdi, rbx                    ; dest = base

    ; Size = keep_tokens * token_stride
    mov rcx, rsi
    mov rdx, rdi
    mov r8, QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN]
    sub r8, rbx
    mov r10, QWORD PTR [g_KVCache + KV_CACHE_N_KV_HEADS]
    mul r10
    mov r10, QWORD PTR [g_KVCache + KV_CACHE_HEAD_DIM]
    mul r10
    shl r8, 2
    call RawrXD_MemCopy

    inc r9
    jmp @@layer_loop

@@done:
    mov QWORD PTR [g_KVCache + KV_CACHE_CUR_SEQ_LEN], rsi
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

RawrXD_KVCacheEvict ENDP

END
