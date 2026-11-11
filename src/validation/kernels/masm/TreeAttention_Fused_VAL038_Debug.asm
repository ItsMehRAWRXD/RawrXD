; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: Fused Tree Attention Kernel - DEBUG VERSION
; ═══════════════════════════════════════════════════════════════════════════════
; Same as VAL038 but with debug instrumentation:
;   - Watchdog counter to detect infinite loops
;   - Loop bounds validation
;   - Debug counters for q/k iterations
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
; External C++ functions for debug output
; ═══════════════════════════════════════════════════════════════════════════════
EXTERN printf:PROC

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

; Debug counters (qword = 64-bit)
ALIGN 8
debug_q_iterations      DQ      0
debug_k_iterations        DQ      0
debug_k_max_per_q         DQ      0
debug_abort_counter       DQ      0
debug_iteration_count     DQ      0

; Constants
MAX_ITERATIONS_PER_KERNEL EQU     10000000  ; 10M iterations max (watchdog)
HEAD_DIM                  EQU     64
scale_factor              REAL4   0.125
neg_inf                   REAL4   -1.0e38

; Debug messages
dbg_msg_q_start           DB      "[DEBUG] Starting query %d\n", 0
dbg_msg_q_end             DB      "[DEBUG] Finished query %d, processed %d keys\n", 0
dbg_msg_k_iter            DB      "[DEBUG]  Key iteration %d\n", 0
dbg_msg_watchdog          DB      "[WATCHDOG] Kernel aborted after %llu iterations\n", 0
dbg_msg_bounds_error      DB      "[ERROR] Loop bounds violated: q=%d, k=%d\n", 0

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; ResetDebugCounters
; ═══════════════════════════════════════════════════════════════════════════════
ResetDebugCounters PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    xor     rax, rax
    mov     qword ptr [debug_q_iterations], rax
    mov     qword ptr [debug_k_iterations], rax
    mov     qword ptr [debug_k_max_per_q], rax
    mov     qword ptr [debug_abort_counter], rax
    mov     qword ptr [debug_iteration_count], rax

    pop     rbp
    ret
ResetDebugCounters ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_Fused_VAL038_Debug
;
; Debug version with watchdog and bounds checking
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_Fused_VAL038_Debug PROC FRAME
    ; Prologue with full register preservation
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
    sub     rsp, 256
    .allocstack 256
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    mov     ebx, [rbp+64]               ; ebx = num_q
    mov     esi, [rbp+72]               ; esi = num_k
    mov     rdi, [rbp+80]               ; rdi = tree_mask

    ; Validate inputs
    test    ebx, ebx
    jz      .done                       ; num_q == 0, nothing to do
    test    esi, esi
    jz      .done                       ; num_k == 0, nothing to do

    ; Reset iteration counter for this kernel invocation
    mov     qword ptr [debug_iteration_count], 0

    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    ; Validate q_idx bounds
    cmp     r8d, ebx
    jae     .done                       ; q_idx >= num_q, done

    ; Increment q iteration counter
    inc     qword ptr [debug_q_iterations]

    ; Debug: Print query start (only first 5 queries)
    cmp     r8d, 5
    jae     @F
    push    r8
    lea     rcx, dbg_msg_q_start
    mov     rdx, r8
    call    printf
    add     rsp, 8
@@:

    ; Reset per-query key counter
    mov     qword ptr [rsp+128], 0      ; local_k_count = 0

    ; Load Q row (simplified - just use first element for now)
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    lea     rcx, [r13 + rax]            ; rcx = &Q[q_idx * head_dim]

    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0

.key_loop:
    ; WATCHDOG: Check iteration count
    inc     qword ptr [debug_iteration_count]
    mov     rax, qword ptr [debug_iteration_count]
    cmp     rax, MAX_ITERATIONS_PER_KERNEL
    jb      @F
    
    ; Watchdog triggered - abort
    inc     qword ptr [debug_abort_counter]
    push    rax
    lea     rcx, dbg_msg_watchdog
    mov     rdx, rax
    call    printf
    add     rsp, 8
    jmp     .done
@@:

    ; Validate k_idx bounds
    cmp     r9d, esi
    jae     .next_query                 ; k_idx >= num_k, next query

    ; Increment k iteration counter
    inc     qword ptr [debug_k_iterations]
    inc     qword ptr [rsp+128]         ; local_k_count++

    ; Debug: Print key iteration (only first 3 keys of first query)
    cmp     r8d, 0
    jne     @F
    cmp     r9d, 3
    jae     @F
    push    r9
    lea     rcx, dbg_msg_k_iter
    mov     rdx, r9
    call    printf
    add     rsp, 8
@@:

    ; Check tree mask
    mov     rax, r8
    imul    rax, rsi                    ; rax = q_idx * num_k
    add     rax, r9                     ; rax = q_idx * num_k + k_idx
    cmp     byte ptr [rdi + rax], 0
    je      .skip_key                   ; Skip if masked

    ; Compute dot product (simplified scalar version)
    ; score = dot(Q, K[k_idx]) * scale_factor
    
    mov     rax, r9
    imul    rax, HEAD_DIM * 4
    lea     rdx, [r14 + rax]            ; rdx = &K[k_idx * head_dim]

    ; Simple dot product (first element only for debug)
    movss   xmm0, dword ptr [rcx]       ; Q[0]
    movss   xmm1, dword ptr [rdx]       ; K[0]
    mulss   xmm0, xmm1
    mulss   xmm0, dword ptr [scale_factor]

    ; Accumulate weighted V (simplified)
    mov     rax, r9
    imul    rax, HEAD_DIM * 4
    lea     rdx, [r15 + rax]            ; rdx = &V[k_idx * head_dim]

    ; output[0] += score * V[0] (simplified)
    movss   xmm1, dword ptr [rdx]
    mulss   xmm0, xmm1
    mov     rax, r8
    imul    rax, HEAD_DIM * 4
    addss   xmm0, dword ptr [r12 + rax]
    movss   dword ptr [r12 + rax], xmm0

.skip_key:
    inc     r9d
    jmp     .key_loop

.next_query:
    ; Update max keys per query
    mov     rax, qword ptr [rsp+128]
    cmp     rax, qword ptr [debug_k_max_per_q]
    jbe     @F
    mov     qword ptr [debug_k_max_per_q], rax
@@:

    ; Debug: Print query end (only first 5 queries)
    cmp     r8d, 5
    jae     @F
    push    r8
    push    rax
    lea     rcx, dbg_msg_q_end
    mov     rdx, r8
    mov     r8, rax
    call    printf
    add     rsp, 16
@@:

    inc     r8d
    jmp     .query_loop

.done:
    ; Epilogue
    add     rsp, 256
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
