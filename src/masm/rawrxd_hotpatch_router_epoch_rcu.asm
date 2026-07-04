; ============================================================================
; RawrXD Hotpatch Router - Epoch-RCU with Reader Counters
; ============================================================================
; Phase 4A: Model Integration with Synchronous Block (Option A)
; - 3-slot epoch rotation for RCU pattern
; - Atomic reader counters per epoch
; - Slot-based model descriptor storage
; ============================================================================

; =============================================================================
; External Imports
; =============================================================================
EXTERN ExitProcess:PROC
EXTERN RawrXD_HotpatchModelCleanup:PROC  ; C++ cleanup callback

; =============================================================================
; Data Section - Epoch-RCU State
; =============================================================================
.data

ALIGN 8

; -----------------------------------------------------------------------------
; Epoch Slot State (3-slot rotation for RCU)
; Each slot tracks: model descriptor, reader count, active flag
; -----------------------------------------------------------------------------

; Slot 0 - Epoch N
ALIGN 8
g_Slot0_Model               QWORD 0     ; Model descriptor pointer
g_Slot0_Readers             DWORD 0     ; Active reader count
g_Slot0_Padding             DWORD 0     ; Alignment padding

; Slot 1 - Epoch N+1  
ALIGN 8
g_Slot1_Model               QWORD 0
g_Slot1_Readers             DWORD 0
g_Slot1_Padding             DWORD 0

; Slot 2 - Epoch N+2 (retirement slot)
ALIGN 8
g_Slot2_Model               QWORD 0
g_Slot2_Readers             DWORD 0
g_Slot2_Padding             DWORD 0

; -----------------------------------------------------------------------------
; Global Epoch State
; -----------------------------------------------------------------------------
ALIGN 8
g_CurrentSlotIndex          DWORD 0     ; 0, 1, or 2 - current active slot
g_PendingSlotIndex          DWORD 0     ; Slot with pending model (or -1)
g_EpochCounter              QWORD 0     ; Total epoch transitions

; Legacy globals (maintained for compatibility)
ALIGN 8
g_ActiveModelDescriptor     QWORD 0     ; Points to current slot's model
g_PendingModelDescriptor    QWORD 0     ; Points to pending slot's model
g_InferenceActive           BYTE  0     ; Global inference flag
g_HotpatchCount             QWORD 0     ; Total hotpatches requested
g_DeferredHotpatchCount     QWORD 0     ; Deferred due to active inference

; Constants
HP_EPOCH_MASK               EQU 1
SLOT_COUNT                  EQU 3
INVALID_SLOT                EQU -1

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; RawrXD_RequestHotpatch
; Phase 4A: Synchronous Block - waits for readers to drain before accepting
; 
; Input:  rcx = Pointer to model descriptor (llama_model* or wrapper)
;         rdx = GPU fence handle (0 if none)
; Output: rax = 0 (success), 1 (already pending), 2 (inference active)
; =============================================================================
RawrXD_RequestHotpatch PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    .endprolog
    
    mov rbx, rcx                    ; rbx = model descriptor
    mov rsi, rdx                    ; rsi = GPU fence
    
    ; Check if hotpatch already pending
    mov eax, g_PendingSlotIndex
    cmp eax, INVALID_SLOT
    jne already_pending
    
    ; Phase 4A: Synchronous block - check if we can swap immediately
    ; In Option B (async), this check would be skipped and we'd queue instead
    mov al, g_InferenceActive
    test al, al
    jnz inference_active
    
    ; Check current slot's reader count
    mov r12d, g_CurrentSlotIndex    ; r12d = current slot (0, 1, or 2)
    call GetSlotReaderCount
    test eax, eax
    jnz readers_active              ; Readers still active, can't swap yet
    
    ; Find next slot for rotation
    ; nextSlot = (currentSlot + 1) % 3
    mov eax, r12d
    inc eax
    cmp eax, SLOT_COUNT
    jb slot_ok
    xor eax, eax                    ; Wrap to 0
slot_ok:
    mov edi, eax                    ; edi = next slot index
    
    ; Store model in next slot
    call SetSlotModel               ; Sets g_Slot[edi]_Model = rbx
    
    ; Memory fence before publishing
    sfence
    
    ; Mark as pending
    mov g_PendingSlotIndex, edi
    mov g_PendingModelDescriptor, rbx
    
    ; Increment epoch counter (odd = pending)
    lock inc qword ptr [g_EpochCounter]
    
    ; Increment stats
    lock inc qword ptr [g_HotpatchCount]
    
    xor rax, rax                    ; Return 0 = success
    jmp done
    
already_pending:
    mov rax, 1                      ; Return 1 = already pending
    jmp done
    
inference_active:
    lock inc qword ptr [g_DeferredHotpatchCount]
    mov rax, 2                      ; Return 2 = inference active
    jmp done
    
readers_active:
    lock inc qword ptr [g_DeferredHotpatchCount]
    mov rax, 3                      ; Return 3 = readers active (Phase 4A)
    
done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_RequestHotpatch ENDP

; =============================================================================
; RawrXD_CheckEpochSwap
; Phase 4A: Completes swap and rotates slots
; 
; Output: rax = 0 (no swap), 1 (swap completed)
; =============================================================================
RawrXD_CheckEpochSwap PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    .endprolog
    
    ; Check if there's a pending swap
    mov edi, g_PendingSlotIndex     ; edi = pending slot (or -1)
    cmp edi, INVALID_SLOT
    je no_swap
    
    ; Get current slot
    mov esi, g_CurrentSlotIndex     ; esi = current slot
    
    ; Check if current slot readers have drained
    call GetSlotReaderCountForIndex
    test eax, eax
    jnz no_swap                     ; Readers still active, can't complete
    
    ; Perform slot rotation:
    ; - Current slot becomes retired (will be freed by C++)
    ; - Pending slot becomes current
    ; - Old current moves to retirement queue
    
    ; Calculate retired slot (the one we're leaving)
    ; retired = (current - 1 + 3) % 3
    mov ebx, esi
    dec ebx
    jns retired_ok
    add ebx, SLOT_COUNT             ; Wrap around
retired_ok:
    
    ; Queue retired slot for cleanup (call C++ callback)
    push rdi
    push rsi
    push rbx
    
    ; Get retired slot's model pointer
    mov ecx, ebx
    call GetSlotModel
    mov rcx, rax                    ; rcx = retired model descriptor
    
    ; Call C++ cleanup (if model exists)
    test rcx, rcx
    jz no_cleanup
    call RawrXD_HotpatchModelCleanup
no_cleanup:
    
    pop rbx
    pop rsi
    pop rdi
    
    ; Complete the swap: pending -> current
    mov g_CurrentSlotIndex, edi
    mov rax, g_Slot0_Model[rdi*8]   ; Get pending model
    mov g_ActiveModelDescriptor, rax
    
    ; Clear pending state
    mov g_PendingSlotIndex, INVALID_SLOT
    mov g_PendingModelDescriptor, 0
    
    ; Increment epoch counter (even = complete)
    lock inc qword ptr [g_EpochCounter]
    
    mov rax, 1                      ; Return 1 = swap completed
    jmp swap_done
    
no_swap:
    xor rax, rax                    ; Return 0 = no swap
    
swap_done:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_CheckEpochSwap ENDP

; =============================================================================
; RawrXD_EnterInferenceEpoch
; Called by inference threads before starting work
; Input:  rcx = slot index (0, 1, or 2) - usually current slot
; Output: rax = 0 (success)
; =============================================================================
RawrXD_EnterInferenceEpoch PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Validate slot index
    cmp ecx, SLOT_COUNT
    jae invalid_slot
    
    ; Increment reader count for this slot
    ; Use lock inc for thread safety
    lea rax, [g_Slot0_Readers + rcx*8]
    lock inc dword ptr [rax]
    
    xor rax, rax                    ; Success
    jmp enter_done
    
invalid_slot:
    mov rax, 1                      ; Error: invalid slot
    
enter_done:
    pop rbp
    ret
RawrXD_EnterInferenceEpoch ENDP

; =============================================================================
; RawrXD_ExitInferenceEpoch
; Called by inference threads after completing work
; Input:  rcx = slot index (0, 1, or 2)
; Output: rax = 0 (success)
; =============================================================================
RawrXD_ExitInferenceEpoch PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Validate slot index
    cmp ecx, SLOT_COUNT
    jae invalid_slot_exit
    
    ; Decrement reader count for this slot
    lea rax, [g_Slot0_Readers + rcx*8]
    lock dec dword ptr [rax]
    
    xor rax, rax                    ; Success
    jmp exit_done
    
invalid_slot_exit:
    mov rax, 1                      ; Error: invalid slot
    
exit_done:
    pop rbp
    ret
RawrXD_ExitInferenceEpoch ENDP

; =============================================================================
; RawrXD_GetCurrentEpochSlot
; Returns the current active slot index
; Output: rax = slot index (0, 1, or 2)
; =============================================================================
RawrXD_GetCurrentEpochSlot PROC
    mov eax, g_CurrentSlotIndex
    ret
RawrXD_GetCurrentEpochSlot ENDP

; =============================================================================
; RawrXD_GetSlotReaderCount
; Returns reader count for current slot
; Output: rax = reader count
; =============================================================================
RawrXD_GetSlotReaderCount PROC
    mov ecx, g_CurrentSlotIndex
    ; Fall through to GetSlotReaderCountForIndex
RawrXD_GetSlotReaderCount ENDP

; =============================================================================
; GetSlotReaderCountForIndex (internal)
; Input: ecx = slot index
; Output: eax = reader count
; =============================================================================
GetSlotReaderCountForIndex PROC
    cmp ecx, SLOT_COUNT
    jae invalid_slot_count
    
    mov eax, [g_Slot0_Readers + ecx*8]
    ret
    
invalid_slot_count:
    xor eax, eax                    ; Return 0 for invalid slot
    ret
GetSlotReaderCountForIndex ENDP

; =============================================================================
; SetSlotModel (internal)
; Input: edi = slot index, rbx = model descriptor
; =============================================================================
SetSlotModel PROC
    cmp edi, SLOT_COUNT
    jae set_slot_done
    
    mov [g_Slot0_Model + rdi*8], rbx
    
set_slot_done:
    ret
SetSlotModel ENDP

; =============================================================================
; GetSlotModel (internal)
; Input: ecx = slot index
; Output: rax = model descriptor
; =============================================================================
GetSlotModel PROC
    cmp ecx, SLOT_COUNT
    jae invalid_get_slot
    
    mov rax, [g_Slot0_Model + rcx*8]
    ret
    
invalid_get_slot:
    xor rax, rax
    ret
GetSlotModel ENDP

; =============================================================================
; RawrXD_InitHotpatchSystem
; Initialize the hotpatch system with 3-slot rotation
; Output: rax = 0 (success)
; =============================================================================
RawrXD_InitHotpatchSystem PROC
    ; Zero all slot state
    mov g_Slot0_Model, 0
    mov g_Slot0_Readers, 0
    mov g_Slot1_Model, 0
    mov g_Slot1_Readers, 0
    mov g_Slot2_Model, 0
    mov g_Slot2_Readers, 0
    
    ; Reset epoch state
    mov g_CurrentSlotIndex, 0
    mov g_PendingSlotIndex, INVALID_SLOT
    mov g_EpochCounter, 0
    
    ; Reset legacy globals
    mov g_ActiveModelDescriptor, 0
    mov g_PendingModelDescriptor, 0
    mov g_InferenceActive, 0
    mov g_HotpatchCount, 0
    mov g_DeferredHotpatchCount, 0
    
    xor rax, rax
    ret
RawrXD_InitHotpatchSystem ENDP

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
    mov rsi, 10000                  ; rsi = max iterations (safety)
    
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
; RawrXD_ForceSyncHotpatch
; Force immediate hotpatch (blocks until readers drain)
; =============================================================================
RawrXD_ForceSyncHotpatch PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Wait for current readers to drain
    mov rcx, 0                      ; Infinite timeout
    call RawrXD_WaitForHotpatchComplete
    
    pop rbp
    ret
RawrXD_ForceSyncHotpatch ENDP

; =============================================================================
; RawrXD_ExecuteInferenceStep
; Stub for inference execution - Phase 4A: Instrumented with epoch enter/exit
; =============================================================================
RawrXD_ExecuteInferenceStep PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    ; Get current slot and enter epoch
    call RawrXD_GetCurrentEpochSlot
    mov ecx, eax
    call RawrXD_EnterInferenceEpoch
    
    ; ... inference work would go here ...
    
    ; Exit epoch
    call RawrXD_GetCurrentEpochSlot
    mov ecx, eax
    call RawrXD_ExitInferenceEpoch
    
    xor rax, rax
    pop rbp
    ret
RawrXD_ExecuteInferenceStep ENDP

END
