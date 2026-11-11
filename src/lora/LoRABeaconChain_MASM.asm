; LoRA Beacon Chain Execution for MASM x64
; Phase 18D: Multi-Adapter Composition via Linked List Traversal
; ============================================================================
; This module extends the single-adapter LoRA implementation to support
; chained adapter execution. It traverses a linked list of beacon states,
; applying each adapter sequentially.

; Data Structure Offsets (LoRABeaconState - 64 bytes)
BEACON_VERSION      EQU 0
BEACON_STATUS       EQU 4
BEACON_RANK         EQU 8
BEACON_HIDDEN_DIM   EQU 12
BEACON_PTR_A        EQU 16
BEACON_PTR_B        EQU 24
BEACON_SCALE        EQU 32
BEACON_NEXT         EQU 40
BEACON_WEIGHT       EQU 48

; Beacon Status Values
BEACON_INACTIVE     EQU 0
BEACON_ACTIVE       EQU 1
BEACON_UPDATING     EQU 2
BEACON_COMPOSITE    EQU 3

; Chain Structure Offsets (LoRABeaconChain - 64 bytes)
CHAIN_COUNT         EQU 0
CHAIN_ACTIVE        EQU 4
CHAIN_HEAD          EQU 8
CHAIN_TAIL          EQU 16
CHAIN_FLAGS         EQU 24

; Chain Flags
CHAIN_FLAG_BLEND    EQU 1      ; Weighted blend mode
CHAIN_FLAG_PARALLEL EQU 2      ; Parallel execution (not implemented)

; ============================================================================
; External Symbols (defined in C++ LoRABeaconInterface.cpp)
; ============================================================================
EXTERNDEF g_beacon_chain:QWORD
EXTERNDEF g_beacon_state:QWORD

.code

; ============================================================================
; Macro: CHECK_CHAIN
; Purpose: Check if a beacon chain is active
; Output: RAX = address of chain struct
; Clobbers: RAX
; ============================================================================
CHECK_CHAIN MACRO
    mov     rax, OFFSET g_beacon_chain  ; Get address of chain struct
    mov     ecx, DWORD PTR [rax + CHAIN_ACTIVE]
    test    ecx, ecx
    jz      no_chain_active
ENDM

; ============================================================================
; Macro: LORA_APPLY_SINGLE_ADDITIVE
; Purpose: Apply single LoRA adapter additively to existing result
; Input:  RCX = current result pointer (accumulator)
;         RDX = input pointer (x)
;         R8  = beacon state pointer
;         R9  = token_count
; Output: Result updated in-place: result += scale * B * A * input
; Clobbers: YMM0-YMM15, RAX, RBX, R10-R15
; ============================================================================
LORA_APPLY_SINGLE_ADDITIVE MACRO
    LOCAL compute_loop, row_loop, col_loop, rows_done, cols_done
    LOCAL output_loop, inner_loop, inner_done, done_compute
    LOCAL token_loop, token_done, tokens_done
    
    ; Save registers
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbx
    
    ; Load beacon parameters
    mov     r15, r8                     ; R15 = beacon state
    mov     r12, QWORD PTR [r15 + BEACON_PTR_A]    ; R12 = A
    mov     r13, QWORD PTR [r15 + BEACON_PTR_B]    ; R13 = B
    mov     r14d, DWORD PTR [r15 + BEACON_RANK]     ; R14D = rank
    mov     r15d, DWORD PTR [r15 + BEACON_HIDDEN_DIM] ; R15D = hidden_dim
    
    ; Load scale factor
    vbroadcastss ymm15, DWORD PTR [r8 + BEACON_SCALE]  ; YMM15 = scale
    
    ; Allocate stack space for temp buffer (rank floats, aligned)
    sub     rsp, 256
    mov     rbx, rsp                    ; RBX = temp buffer
    
    ; Get total tokens
    mov     r10, r9                     ; R10 = token_count
    xor     r11, r11                    ; R11 = token index
    
token_loop:
    cmp     r11, r10
    jge     tokens_done
    
    ; Compute offset for this token
    mov     rax, r11
    imul    rax, r15                    ; RAX = token * hidden_dim
    
    ; Get pointers for this token
    lea     rsi, [rdx + rax*4]          ; RSI = input[token]
    lea     rdi, [rcx + rax*4]          ; RDI = result[token] (accumulator)
    
    ; Step 1: temp = A * input (rank x 1)
    xor     ecx, ecx                    ; ECX = row index
row_loop:
    cmp     ecx, r14d
    jge     rows_done
    
    ; Compute dot product for this row
    vxorps  ymm0, ymm0, ymm0           ; YMM0 = accumulator
    
    xor     eax, eax                    ; EAX = column index
col_loop:
    cmp     eax, r15d
    jge     cols_done
    
    ; Load A[row, col] and input[col]
    mov     r8d, ecx
    imul    r8d, r15d                   ; R8D = row * hidden_dim
    add     r8d, eax                    ; R8D = row * hidden_dim + col
    vbroadcastss ymm1, DWORD PTR [r12 + r8*4]  ; YMM1 = A[row, col]
    
    vmovups ymm2, YMMWORD PTR [rsi + rax*4]    ; YMM2 = input[col:col+8]
    vfmadd231ps ymm0, ymm1, ymm2       ; YMM0 += A * input
    
    add     eax, 8
    jmp     col_loop
    
cols_done:
    ; Horizontal sum of YMM0 into temp[row]
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    vmovss  DWORD PTR [rbx + rcx*4], xmm0
    
    inc     ecx
    jmp     row_loop
    
rows_done:
    ; Step 2: Compute scale * B * temp and add to result
    ; For each output o: result[o] += scale * dot(B[o,:], temp[:])
    xor     eax, eax                    ; EAX = output index
output_loop:
    cmp     eax, r15d
    jge     token_done
    
    ; Compute B[o,:] dot temp[:]
    vxorps  ymm0, ymm0, ymm0           ; YMM0 = accumulator
    
    xor     ecx, ecx                    ; ECX = rank index
inner_loop:
    cmp     ecx, r14d
    jge     inner_done
    
    ; Load B[o, r] and temp[r]
    mov     r8d, eax
    imul    r8d, r14d                   ; R8D = o * rank
    add     r8d, ecx                    ; R8D = o * rank + r
    vbroadcastss ymm1, DWORD PTR [r13 + r8*4]   ; YMM1 = B[o, r]
    
    vbroadcastss ymm2, DWORD PTR [rbx + rcx*4]  ; YMM2 = temp[r]
    vfmadd231ps ymm0, ymm1, ymm2       ; YMM0 += B * temp
    
    inc     ecx
    jmp     inner_loop
    
inner_done:
    ; Apply scale and add to existing result
    vmulps  ymm0, ymm0, ymm15          ; YMM0 = scale * (B * temp)
    
    ; Load current result and add
    vmovups ymm1, YMMWORD PTR [rdi + rax*4]
    vaddps  ymm0, ymm0, ymm1           ; YMM0 = result + scale * delta
    
    ; Store back
    vmovups YMMWORD PTR [rdi + rax*4], ymm0
    
    add     eax, 8
    jmp     output_loop
    
token_done:
    ; Next token
    inc     r11
    jmp     token_loop
    
tokens_done:
    ; Restore stack
    add     rsp, 256
    
    ; Restore registers
    pop     rbx
    pop     r15
    pop     r14
    pop     r13
    pop     r12
ENDM

; ============================================================================
; Function: LoRA_Apply_Chain
; Purpose: Main entry point for chained LoRA execution
; Input:  RCX = base_output pointer (W_0 * x)
;         RDX = input pointer (x)
;         R8  = result pointer (output)
;         R9  = token_count
; Output: Result written to R8
; ============================================================================
.code
LoRA_Apply_Chain PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
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
    .endprolog
    
    ; Check if chain exists
    CHECK_CHAIN
    
    ; Initialize result with base output
    mov     rsi, rcx                    ; RSI = base_output
    mov     rdi, r8                     ; RDI = result
    mov     rcx, r9                     ; RCX = token_count
    imul    rcx, rcx, 768               ; Assume 768 hidden dim * 4 bytes
    shr     rcx, 2                      ; Divide by 4 for dword count
    rep movsd                         ; Copy base to result
    
    ; Get chain head
    mov     r15, rax                    ; R15 = chain pointer
    mov     r14, QWORD PTR [r15 + CHAIN_HEAD]  ; R14 = first beacon
    
    ; Check chain flags
    mov     eax, DWORD PTR [r15 + CHAIN_FLAGS]
    test    eax, CHAIN_FLAG_BLEND
    jnz     do_blend_mode
    
    ; Sequential mode: iterate through linked list
chain_loop:
    test    r14, r14
    jz      chain_done
    
    ; Apply this adapter (additive to current result)
    mov     r8, r14                     ; R8 = current beacon
    ; RCX = result (already set), RDX = input, R9 = token_count
    LORA_APPLY_SINGLE_ADDITIVE
    
    ; Move to next beacon
    mov     r14, QWORD PTR [r14 + BEACON_NEXT]
    jmp     chain_loop
    
do_blend_mode:
    ; Weighted blend mode: pre-blended weights in first beacon
    ; Just apply once with blended weights
    mov     r8, r14
    LORA_APPLY_SINGLE_ADDITIVE
    jmp     chain_done
    
chain_done:
    ; Success
    xor     rax, rax                    ; Return 0 (success)
    jmp     exit_func
    
no_chain_active:
    ; No chain active - just copy base to result (already done above)
    xor     rax, rax                    ; Return 0 (success)
    
exit_func:
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
LoRA_Apply_Chain ENDP

; ============================================================================
; Function: LoRA_Check_Chain
; Purpose: Check if a beacon chain is currently active
; Input:  None
; Output: RAX = 1 if chain active, 0 if not
; ============================================================================
LoRA_Check_Chain PROC
    mov     rax, OFFSET g_beacon_chain
    mov     rax, QWORD PTR [rax]        ; Get chain pointer
    test    rax, rax
    setnz   al
    movzx   rax, al
    ret
LoRA_Check_Chain ENDP

; ============================================================================
; Function: LoRA_Get_Chain_Count
; Purpose: Get number of adapters in active chain
; Input:  None
; Output: RAX = adapter count (0 if no chain)
; ============================================================================
LoRA_Get_Chain_Count PROC
    mov     rax, OFFSET g_beacon_chain
    mov     rax, QWORD PTR [rax]        ; Get chain pointer
    test    rax, rax
    jz      no_chain
    
    mov     eax, DWORD PTR [rax + CHAIN_COUNT]
    ret
    
no_chain:
    xor     rax, rax
    ret
LoRA_Get_Chain_Count ENDP

; ============================================================================
; Function: LoRA_Get_Chain_Head
; Purpose: Get pointer to first beacon in chain
; Input:  None
; Output: RAX = head beacon pointer (NULL if no chain)
; ============================================================================
LoRA_Get_Chain_Head PROC
    mov     rax, OFFSET g_beacon_chain
    mov     rax, QWORD PTR [rax]        ; Get chain pointer
    test    rax, rax
    jz      no_chain_head
    
    mov     rax, QWORD PTR [rax + CHAIN_HEAD]
    ret
    
no_chain_head:
    xor     rax, rax
    ret
LoRA_Get_Chain_Head ENDP

; ============================================================================
; Function: LoRA_Apply_Single
; Purpose: Apply single LoRA (backward compatible)
; Input:  RCX = base_output
;         RDX = input
;         R8  = result
;         R9  = token_count
; Output: Result in R8
; ============================================================================
LoRA_Apply_Single PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
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
    .endprolog
    
    ; Check for single beacon (non-chain)
    mov     r15, OFFSET g_beacon_state
    mov     eax, DWORD PTR [r15 + BEACON_STATUS]
    cmp     eax, BEACON_ACTIVE
    jne     single_no_beacon
    
    ; Load beacon parameters
    mov     r12, QWORD PTR [r15 + BEACON_PTR_A]
    mov     r13, QWORD PTR [r15 + BEACON_PTR_B]
    mov     r14d, DWORD PTR [r15 + BEACON_RANK]
    mov     r15d, DWORD PTR [r15 + BEACON_HIDDEN_DIM]
    
    ; Initialize result with base
    mov     rsi, rcx
    mov     rdi, r8
    mov     rcx, r9
    imul    rcx, rcx, r15
    shr     rcx, 2
    rep movsd
    
    ; Apply single adapter
    mov     rcx, r8                     ; RCX = result
    ; RDX = input (already set)
    mov     r8, r15                     ; R8 = beacon (using R15 from above)
    ; R9 = token_count (already set)
    
    ; Call additive apply (same as single for first application)
    LORA_APPLY_SINGLE_ADDITIVE
    
    xor     rax, rax
    jmp     single_exit
    
single_no_beacon:
    ; No beacon - just copy base to result
    mov     rsi, rcx
    mov     rdi, r8
    mov     rcx, r9
    imul    rcx, rcx, 768               ; Assume 768 hidden dim
    shr     rcx, 2
    rep movsd
    xor     rax, rax
    
single_exit:
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
LoRA_Apply_Single ENDP

END
