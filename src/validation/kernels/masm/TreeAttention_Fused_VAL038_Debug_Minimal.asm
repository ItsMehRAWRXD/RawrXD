; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: Fused Tree Attention Kernel - DEBUG MINIMAL VERSION
; ═══════════════════════════════════════════════════════════════════════════════
; No printf calls - just counters and watchdog
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; Public Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_Fused_VAL038_Debug
PUBLIC ResetDebugCounters
PUBLIC debug_q_iterations
PUBLIC debug_k_iterations
PUBLIC debug_k_max_per_q
PUBLIC debug_abort_counter
PUBLIC debug_iteration_count

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

; Debug counters (qword = 64-bit)
ALIGN 8
debug_q_iterations      DQ      0
debug_k_iterations      DQ      0
debug_k_max_per_q       DQ      0
debug_abort_counter     DQ      0
debug_iteration_count   DQ      0

; Constants
MAX_ITERATIONS_PER_KERNEL EQU     10000000  ; 10M iterations max (watchdog)
HEAD_DIM                EQU     64
scale_factor            REAL4   0.125
neg_inf                 REAL4   -1.0e38

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; ResetDebugCounters - Clear all debug counters
; ═══════════════════════════════════════════════════════════════════════════════
ResetDebugCounters PROC
    xor     rax, rax
    mov     qword ptr [debug_q_iterations], rax
    mov     qword ptr [debug_k_iterations], rax
    mov     qword ptr [debug_k_max_per_q], rax
    mov     qword ptr [debug_abort_counter], rax
    mov     qword ptr [debug_iteration_count], rax
    ret
ResetDebugCounters ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_Fused_VAL038_Debug - Fused attention with debug counters
; ═══════════════════════════════════════════════════════════════════════════════
; Parameters (Windows x64 ABI):
;   RCX = output          (float*)
;   RDX = Q               (const float*)
;   R8  = K               (const float*)
;   R9  = V               (const float*)
;   [RBP+64]  = num_q     (uint32_t)
;   [RBP+72]  = num_k     (uint32_t)
;   [RBP+80]  = tree_mask (const uint8_t*)
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_Fused_VAL038_Debug PROC FRAME
    push    rbp
    .pushreg rbp
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
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64
    .allocstack 64
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    
    ; Load stack parameters (after 8 pushed registers = 64 bytes, retaddr at rbp+8)
    mov     ebx, dword ptr [rbp+16]     ; ebx = num_q (5th param)
    mov     esi, dword ptr [rbp+24]     ; esi = num_k (6th param)
    mov     rdi, qword ptr [rbp+32]     ; rdi = tree_mask (7th param)

    ; Validate inputs
    test    ebx, ebx
    jz      .done                       ; num_q == 0
    test    esi, esi
    jz      .done                       ; num_k == 0

    ; Reset iteration counter
    mov     qword ptr [debug_iteration_count], 0

    ; Outer loop: iterate over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    ; Check q_idx bounds
    cmp     r8d, ebx
    jae     .done                       ; q_idx >= num_q

    ; Increment q iteration counter
    inc     qword ptr [debug_q_iterations]

    ; Reset per-query key counter (stored in stack)
    mov     qword ptr [rsp+32], 0       ; local_k_count = 0

    ; Compute Q row pointer: &Q[q_idx * HEAD_DIM]
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    lea     r10, [r13 + rax]            ; r10 = &Q[q_idx * head_dim]

    ; Inner loop: iterate over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0

.key_loop:
    ; WATCHDOG: Check global iteration count
    inc     qword ptr [debug_iteration_count]
    mov     rax, qword ptr [debug_iteration_count]
    cmp     rax, MAX_ITERATIONS_PER_KERNEL
    jb      .check_k_bounds
    
    ; Watchdog triggered - abort
    inc     qword ptr [debug_abort_counter]
    jmp     .done

.check_k_bounds:
    ; Check if k_idx >= num_k
    cmp     r9d, esi
    jae     .next_query                 ; k_idx >= num_k, move to next query

    ; Increment k iteration counter
    inc     qword ptr [debug_k_iterations]
    inc     qword ptr [rsp+32]          ; local_k_count++

    ; Check tree mask: mask[q_idx * num_k + k_idx]
    ; Use 32-bit operations for mask indexing to avoid 64-bit overflow issues
    mov     eax, r8d                    ; eax = q_idx
    mul     esi                         ; edx:eax = q_idx * num_k (32-bit mul)
    ; Result in eax (lower 32 bits), ignore edx for small values
    add     eax, r9d                    ; eax = q_idx * num_k + k_idx
    movzx   eax, byte ptr [rdi + rax]   ; eax = mask[index]
    test    al, al
    jz      .skip_key                   ; Skip if mask is 0

    ; Compute dot product Q · K[k_idx] (simplified - first element only)
    mov     eax, r9d
    imul    rax, HEAD_DIM * 4
    lea     r11, [r14 + rax]            ; r11 = &K[k_idx * head_dim]

    ; Simple computation: output[q_idx] += Q[0] * K[0] * scale * V[0]
    movss   xmm0, dword ptr [r10]       ; xmm0 = Q[0]
    movss   xmm1, dword ptr [r11]       ; xmm1 = K[0]
    mulss   xmm0, xmm1                  ; xmm0 = Q[0] * K[0]
    mulss   xmm0, dword ptr [scale_factor]  ; xmm0 *= scale

    ; Load V and accumulate
    mov     eax, r9d
    imul    rax, HEAD_DIM * 4
    lea     r11, [r15 + rax]            ; r11 = &V[k_idx * head_dim]
    movss   xmm1, dword ptr [r11]       ; xmm1 = V[0]
    mulss   xmm0, xmm1                  ; xmm0 *= V[0]

    ; Accumulate to output
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    addss   xmm0, dword ptr [r12 + rax]
    movss   dword ptr [r12 + rax], xmm0

.skip_key:
    ; Increment k_idx and continue inner loop
    inc     r9d
    jmp     .key_loop

.next_query:
    ; Update max keys per query
    mov     rax, qword ptr [rsp+32]     ; rax = local_k_count
    cmp     rax, qword ptr [debug_k_max_per_q]
    jbe     .continue_query
    mov     qword ptr [debug_k_max_per_q], rax

.continue_query:
    ; Increment q_idx and continue outer loop
    inc     r8d
    jmp     .query_loop

.done:
    ; Epilogue
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttention_Fused_VAL038_Debug ENDP

END
