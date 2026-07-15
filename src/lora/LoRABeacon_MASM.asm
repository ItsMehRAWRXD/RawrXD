; LoRA Beacon Interface for MASM x64
; Phase 18C/18D: Zero-Dependency Assembly Hot Path
; ============================================================================
; This module provides the assembly-side interface for LoRA computation.
; It polls the beacon state directly from memory without C++ runtime calls.

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

; ============================================================================
; External Symbols (provided by C++ data provider)
; ============================================================================
EXTERNDEF g_beacon_state:QWORD      ; Address of LoRABeaconState struct
EXTERNDEF g_matrix_a_storage:DWORD  ; Aligned A matrix storage
EXTERNDEF g_matrix_b_storage:DWORD  ; Aligned B matrix storage

; ============================================================================
; Macro: CHECK_BEACON
; Purpose: Check if LoRA is active and branch accordingly
; Input:  None (reads g_beacon_state)
; Output: RAX = beacon state pointer (address of g_beacon_state)
; Clobbers: RAX, RCX, RDX
; ============================================================================
CHECK_BEACON MACRO
    mov     rax, OFFSET g_beacon_state  ; Get address of beacon state struct
    mov     ecx, DWORD PTR [rax + BEACON_STATUS]
    cmp     ecx, BEACON_ACTIVE
    je      beacon_active
    cmp     ecx, BEACON_COMPOSITE
    je      beacon_composite
    ; Fall through to beacon_inactive
beacon_inactive LABEL NEAR
ENDM

; ============================================================================
; Macro: LOAD_BEACON_PTRS
; Purpose: Load A and B matrix pointers from beacon
; Input:  R15 = beacon state pointer
; Output: R12 = ptr_A, R13 = ptr_B
;         R14D = rank, R15D = hidden_dim
; Clobbers: R12, R13, R14, R15
; ============================================================================
LOAD_BEACON_PTRS MACRO
    mov     r12, QWORD PTR [r15 + BEACON_PTR_A]    ; R12 = A
    mov     r13, QWORD PTR [r15 + BEACON_PTR_B]    ; R13 = B
    mov     r14d, DWORD PTR [r15 + BEACON_RANK]     ; R14D = rank
    mov     r15d, DWORD PTR [r15 + BEACON_HIDDEN_DIM] ; R15D = hidden_dim
ENDM

; ============================================================================
; Macro: LORA_APPLY_SINGLE
; Purpose: Apply single LoRA adapter: result += scale * B * A * input
; Input:  RDI = base_output pointer
;         RSI = input pointer  
;         RDX = result pointer
;         R12 = A matrix pointer
;         R13 = B matrix pointer
;         R14D = rank
;         R15D = hidden_dim
;         XMM0 = scale_factor
; Output: Result stored in [RDX]
; Clobbers: YMM0-YMM15, RAX, RBX, RCX
; ============================================================================
LORA_APPLY_SINGLE MACRO
    LOCAL compute_loop, row_loop, col_loop, rows_done, cols_done
    LOCAL output_loop, inner_loop, inner_done, done_compute
    
    ; Allocate stack space for temp buffer (rank floats)
    sub     rsp, 256                    ; Align to 32 bytes, max rank 64
    mov     rbx, rsp                    ; RBX = temp buffer
    
    ; Step 1: temp = A * input (rank x 1)
    ; For each row r in A: temp[r] = dot(A[r,:], input[:])
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
    ; Step 2: result = base + scale * B * temp
    ; For each output o: result[o] = base[o] + scale * dot(B[o,:], temp[:])
    xor     eax, eax                    ; EAX = output index
output_loop:
    cmp     eax, r15d
    jge     done_compute
    
    ; Load base_output[o]
    vbroadcastss ymm2, DWORD PTR [rdi + rax*4]  ; YMM2 = base[o]
    
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
    
    vbroadcastss ymm3, DWORD PTR [rbx + rcx*4]  ; YMM3 = temp[r]
    vfmadd231ps ymm0, ymm1, ymm3       ; YMM0 += B * temp
    
    inc     ecx
    jmp     inner_loop
    
inner_done:
    ; Apply scale and add to base
    vmulps  ymm0, ymm0, ymm0           ; YMM0 = scale * (B * temp)
    vaddps  ymm0, ymm0, ymm2           ; YMM0 = base + scale * delta
    
    ; Store result
    vmovups YMMWORD PTR [rdx + rax*4], ymm0
    
    add     eax, 8
    jmp     output_loop
    
done_compute:
    add     rsp, 256                    ; Restore stack
ENDM

; ============================================================================
; Function: LoRA_Apply_Beacon
; Purpose: Main entry point for LoRA application from MASM pipeline
; Input:  RCX = base_output pointer (W_0 * x)
;         RDX = input pointer (x)
;         R8  = result pointer
;         R9  = token_count
; Output: None (result written to R8)
; ============================================================================
.code
LoRA_Apply_Beacon PROC FRAME
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
    
    ; Check beacon status
    mov     r15, OFFSET g_beacon_state  ; Get address of beacon state struct
    
    mov     ecx, DWORD PTR [r15 + BEACON_STATUS]
    cmp     ecx, BEACON_ACTIVE
    je      @@beacon_active
    cmp     ecx, BEACON_COMPOSITE
    je      @@beacon_composite
    jmp     @@beacon_inactive              ; Any other status = inactive
    
@@beacon_active:
    jmp     do_single_lora
    
@@beacon_composite:
    jmp     do_chain_lora
    
@@beacon_inactive:
    mov     eax, DWORD PTR [r15 + BEACON_STATUS]
    cmp     eax, BEACON_ACTIVE
    je      do_single_lora
    cmp     eax, BEACON_COMPOSITE
    je      do_chain_lora
    
    ; Beacon inactive - just copy base to result
    mov     rsi, rcx                    ; RSI = base
    mov     rdi, r8                     ; RDI = result
    mov     rcx, r9                     ; RCX = token_count
    rep movsb
    jmp     exit_func
    
do_single_lora:
    ; Load beacon parameters
    LOAD_BEACON_PTRS
    
    ; Load scale factor
    vbroadcastss ymm0, DWORD PTR [r15 + BEACON_SCALE - 40]  ; Adjust offset
    
    ; Apply single LoRA
    mov     rdi, rcx                    ; RDI = base_output
    mov     rsi, rdx                    ; RSI = input
    mov     rdx, r8                     ; RDX = result
    LORA_APPLY_SINGLE
    jmp     exit_func
    
do_chain_lora:
    ; Phase 18D: Chain-of-Beacon execution
    ; Iterate through linked list of adapters
    mov     r14, QWORD PTR [r15 + BEACON_NEXT]  ; R14 = next adapter
    
chain_loop:
    test    r14, r14
    jz      exit_func                   ; End of chain
    
    ; Load this adapter's pointers
    mov     r15, r14                    ; R15 = current beacon
    LOAD_BEACON_PTRS
    
    ; Apply this adapter
    mov     rdi, rcx
    mov     rsi, rdx
    mov     rdx, r8
    LORA_APPLY_SINGLE
    
    ; Move to next adapter
    mov     r14, QWORD PTR [r15 + BEACON_NEXT]
    jmp     chain_loop
    
exit_func:
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
LoRA_Apply_Beacon ENDP

; ============================================================================
; Function: LoRA_Check_Beacon
; Purpose: Quick check if LoRA is active (for conditional branching)
; Input:  None
; Output: RAX = 1 if active, 0 if inactive
; ============================================================================
LoRA_Check_Beacon PROC
    mov     rax, OFFSET g_beacon_state  ; Get address of beacon state struct
    mov     eax, DWORD PTR [rax + BEACON_STATUS]
    cmp     eax, BEACON_ACTIVE
    sete    al
    movzx   rax, al
    ret
LoRA_Check_Beacon ENDP

; ============================================================================
; Function: LoRA_Get_Beacon_Ptrs
; Purpose: Get A and B matrix pointers for external use
; Input:  RCX = pointer to store A
;         RDX = pointer to store B
; Output: None
; ============================================================================
LoRA_Get_Beacon_Ptrs PROC
    mov     r8, OFFSET g_beacon_state  ; Get address of beacon state struct
    mov     r9, QWORD PTR [r8 + BEACON_PTR_A]
    mov     QWORD PTR [rcx], r9
    mov     r9, QWORD PTR [r8 + BEACON_PTR_B]
    mov     QWORD PTR [rdx], r9
    ret
LoRA_Get_Beacon_Ptrs ENDP

END
