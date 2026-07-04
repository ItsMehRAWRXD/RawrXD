; ============================================================================
; RawrXD Hotpatch Router - Simplified Working Version
; ============================================================================
; Minimal hotpatch router that assembles cleanly with ml64
; ============================================================================

; External Imports
EXTERN ExitProcess:PROC

; =============================================================================
; Data Section
; =============================================================================
.data

ALIGN 8
g_ActiveModelDescriptor     QWORD 0
g_PendingModelDescriptor    QWORD 0
g_EpochCounter              QWORD 0
g_InferenceActive           BYTE  0
g_HotpatchCount             QWORD 0
g_DeferredHotpatchCount     QWORD 0

; Constants
HP_EPOCH_MASK               EQU 1

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; RawrXD_RequestHotpatch
; Input:  rcx = Pointer to model descriptor
;         rdx = GPU fence handle (0 if none)
; Output: rax = 0 (success), 1 (already pending), 2 (inference active)
; =============================================================================
RawrXD_RequestHotpatch PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    .endprolog
    
    mov rbx, rcx                    ; rbx = model descriptor
    mov rsi, rdx                    ; rsi = GPU fence
    
    ; Check if inference is active
    mov al, g_InferenceActive
    test al, al
    jnz inference_active
    
    ; Check if hotpatch already pending
    mov rax, g_PendingModelDescriptor
    test rax, rax
    jnz already_pending
    
    ; Store fence before publishing
    sfence
    
    ; Set pending model
    mov g_PendingModelDescriptor, rbx
    
    ; Increment epoch (odd = pending)
    lock inc qword ptr [g_EpochCounter]
    
    ; Increment stats
    lock inc qword ptr [g_HotpatchCount]
    
    xor rax, rax                    ; Return 0 = success
    jmp done
    
already_pending:
    mov rax, 1                      ; Return 1 = already pending
    jmp done
    
inference_active:
    mov rax, 2                      ; Return 2 = inference active
    
done:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_RequestHotpatch ENDP

; =============================================================================
; RawrXD_CheckEpochSwap
; Output: rax = 0 (no swap), 1 (swap completed)
; =============================================================================
RawrXD_CheckEpochSwap PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    .endprolog
    
    ; Check epoch counter
    mov rax, g_EpochCounter
    test rax, HP_EPOCH_MASK         ; Check if odd (pending)
    jz no_swap
    
    ; Load pending model
    mov rbx, g_PendingModelDescriptor
    test rbx, rbx
    jz no_swap
    
    ; Perform swap
    mov g_ActiveModelDescriptor, rbx
    mov g_PendingModelDescriptor, 0
    
    ; Increment epoch again (even = complete)
    lock inc qword ptr [g_EpochCounter]
    
    mov rax, 1                      ; Return 1 = swap completed
    jmp swap_done
    
no_swap:
    xor rax, rax                    ; Return 0 = no swap
    
swap_done:
    pop rbx
    pop rbp
    ret
RawrXD_CheckEpochSwap ENDP

; =============================================================================
; RawrXD_WaitForHotpatchComplete
; Input:  rcx = timeout in ms (0 = infinite)
; Output: rax = 0 (success), 1 (timeout)
; =============================================================================
RawrXD_WaitForHotpatchComplete PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    .endprolog
    
    mov rbx, rcx                    ; rbx = timeout
    mov rsi, 1000                   ; rsi = max iterations (safety)
    
wait_loop:
    ; Check if epoch is even (complete)
    mov rax, g_EpochCounter
    test rax, HP_EPOCH_MASK
    jz hotpatch_complete
    
    ; Small delay
    pause
    
    dec rsi
    jnz wait_loop
    
    ; Timeout
    mov rax, 1
    jmp wait_done
    
hotpatch_complete:
    xor rax, rax                    ; Return 0 = success
    
wait_done:
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_WaitForHotpatchComplete ENDP

; =============================================================================
; RawrXD_InitHotpatchSystem
; Output: rax = 0 (success)
; =============================================================================
RawrXD_InitHotpatchSystem PROC
    ; Zero all globals
    mov g_ActiveModelDescriptor, 0
    mov g_PendingModelDescriptor, 0
    mov g_EpochCounter, 0
    mov g_InferenceActive, 0
    mov g_HotpatchCount, 0
    mov g_DeferredHotpatchCount, 0
    xor rax, rax
    ret
RawrXD_InitHotpatchSystem ENDP

; =============================================================================
; RawrXD_ExecuteInferenceStep
; Stub for inference execution
; =============================================================================
RawrXD_ExecuteInferenceStep PROC
    xor rax, rax
    ret
RawrXD_ExecuteInferenceStep ENDP

; =============================================================================
; RawrXD_ForceSyncHotpatch
; Force immediate hotpatch (blocks)
; =============================================================================
RawrXD_ForceSyncHotpatch PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Set inference inactive
    mov g_InferenceActive, 0
    
    ; Request hotpatch
    call RawrXD_RequestHotpatch
    
    ; Wait for completion
    mov rcx, 5000                   ; 5 second timeout
    call RawrXD_WaitForHotpatchComplete
    
    pop rbp
    ret
RawrXD_ForceSyncHotpatch ENDP

; =============================================================================
; Status Query Functions (for JSON control commands)
; =============================================================================

; RawrXD_GetActiveEpochSlot - Returns handle to active model
RawrXD_GetActiveEpochSlot PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    mov rax, g_ActiveModelDescriptor
    pop rbp
    ret
RawrXD_GetActiveEpochSlot ENDP

; RawrXD_GetShadowEpochSlot - Returns handle to pending/shadow model
RawrXD_GetShadowEpochSlot PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    mov rax, g_PendingModelDescriptor
    pop rbp
    ret
RawrXD_GetShadowEpochSlot ENDP

; RawrXD_GetRetiredEpochSlot - Returns 0 (no retired slot tracking yet)
RawrXD_GetRetiredEpochSlot PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    xor rax, rax
    pop rbp
    ret
RawrXD_GetRetiredEpochSlot ENDP

; RawrXD_GetEpochCounter - Returns current epoch
RawrXD_GetEpochCounter PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    mov rax, g_EpochCounter
    pop rbp
    ret
RawrXD_GetEpochCounter ENDP

; RawrXD_IsSwapPending - Returns 1 if epoch is odd (pending), 0 if even
RawrXD_IsSwapPending PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    mov rax, g_EpochCounter
    and rax, HP_EPOCH_MASK
    pop rbp
    ret
RawrXD_IsSwapPending ENDP

; RawrXD_RollbackToPreviousModel - Stub (returns error for now)
RawrXD_RollbackToPreviousModel PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    mov rax, 99
    pop rbp
    ret
RawrXD_RollbackToPreviousModel ENDP

; =============================================================================
; Inference RCU Functions (Phase 4C)
; =============================================================================

; RawrXD_BeginInference - Mark inference as active, return current epoch
; Output: rax = current epoch counter
RawrXD_BeginInference PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Mark inference active
    mov g_InferenceActive, 1
    
    ; Memory barrier to ensure visibility
    sfence
    
    ; Return current epoch
    mov rax, g_EpochCounter
    
    pop rbp
    ret
RawrXD_BeginInference ENDP

; RawrXD_EndInference - Mark inference as inactive
; Output: rax = 0
RawrXD_EndInference PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Memory barrier before clearing
    sfence
    
    ; Mark inference inactive
    mov g_InferenceActive, 0
    
    xor rax, rax
    pop rbp
    ret
RawrXD_EndInference ENDP

; RawrXD_GetCurrentModelDescriptor - Get active model descriptor
; Output: rax = pointer to active model descriptor (or 0 if none)
RawrXD_GetCurrentModelDescriptor PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    mov rax, g_ActiveModelDescriptor
    
    pop rbp
    ret
RawrXD_GetCurrentModelDescriptor ENDP

; =============================================================================
; Exports
; =============================================================================
PUBLIC RawrXD_RequestHotpatch
PUBLIC RawrXD_CheckEpochSwap
PUBLIC RawrXD_WaitForHotpatchComplete
PUBLIC RawrXD_InitHotpatchSystem
PUBLIC RawrXD_ExecuteInferenceStep
PUBLIC RawrXD_ForceSyncHotpatch
PUBLIC RawrXD_GetActiveEpochSlot
PUBLIC RawrXD_GetShadowEpochSlot
PUBLIC RawrXD_GetRetiredEpochSlot
PUBLIC RawrXD_GetEpochCounter
PUBLIC RawrXD_IsSwapPending
PUBLIC RawrXD_RollbackToPreviousModel
PUBLIC g_ActiveModelDescriptor
PUBLIC g_PendingModelDescriptor
PUBLIC g_EpochCounter
PUBLIC g_HotpatchCount
PUBLIC g_DeferredHotpatchCount
PUBLIC g_InferenceActive

END
