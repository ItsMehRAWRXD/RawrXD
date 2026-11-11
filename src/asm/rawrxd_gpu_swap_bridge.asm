; ============================================================================
; RawrXD GPU Buffer Swap Bridge - MASM64 Implementation
; ============================================================================
; Phase 3: Track 3 - GPU Tensor Upload Pipeline
; 
; This module provides atomic GPU buffer handle swapping that integrates
; with the Epoch-RCU router. When the router rotates epochs, this bridge
; atomically swaps GPU buffer pointers alongside model descriptors.
;
; Key Operations:
;   - RawrXD_SwapGPUBuffer: Atomic swap of GPU buffer handles
;   - RawrXD_GetGPUBuffer: Safe read of current GPU buffer
;   - RawrXD_ReleaseGPUBuffer: Decrement reader count for RCU
;
; Architecture:
;   - 64-byte aligned buffer handles (matches ModelDescriptor alignment)
;   - Atomic operations with memory barriers (sfence/lfence)
;   - Integrates with Epoch-RCU reader counting
; ============================================================================

; Public exports
PUBLIC RawrXD_SwapGPUBuffer
PUBLIC RawrXD_GetGPUBuffer
PUBLIC RawrXD_ReleaseGPUBuffer
PUBLIC RawrXD_PrepareShadowGPUBuffer
PUBLIC RawrXD_CommitGPUBufferSwap

; External imports from Epoch-RCU router
EXTERN RawrXD_CurrentEpoch : QWORD
EXTERN RawrXD_SlotReaders : QWORD
EXTERN RawrXD_GetSlotForEpoch : PROC

; ============================================================================
; Data Section - GPU Buffer Registry
; ============================================================================
.DATA

; GPU Buffer Registry - Parallel to ModelDescriptor slots
; Each entry: { bufferHandle, fenceHandle, uploadComplete, epoch }
; Aligned to 64 bytes for cache-line optimization
ALIGN 64
RawrXD_GPUBufferRegistry LABEL QWORD
    ; Slot 0: Active
    DQ 0                    ; bufferHandle (VulkanBuffer*)
    DQ 0                    ; fenceHandle (VkFence)
    DQ 0                    ; uploadComplete flag
    DQ 0                    ; assignedEpoch
    DQ 0, 0, 0, 0           ; padding to 64 bytes
    
    ; Slot 1: Shadow A
    DQ 0
    DQ 0
    DQ 0
    DQ 0
    DQ 0, 0, 0, 0
    
    ; Slot 2: Shadow B
    DQ 0
    DQ 0
    DQ 0
    DQ 0
    DQ 0, 0, 0, 0

; Current active GPU buffer slot (0-2)
ALIGN 8
RawrXD_ActiveGPUSlot DQ 0

; Shadow slot being prepared (for upload)
ALIGN 8
RawrXD_PreparingGPUSlot DQ 1

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; RawrXD_PrepareShadowGPUBuffer
;   Prepare a shadow slot for GPU buffer upload
; 
; Input:  RCX = slotIndex (1 or 2 for shadow slots)
;         RDX = bufferHandle (VulkanBuffer*)
;         R8  = fenceHandle (VkFence)
; Output: RAX = 0 on success, -1 on error
; ----------------------------------------------------------------------------
RawrXD_PrepareShadowGPUBuffer PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog
    
    ; Validate slot index (must be 1 or 2)
    cmp rcx, 1
    jb error_invalid_slot
    cmp rcx, 2
    ja error_invalid_slot
    
    ; Calculate slot offset in registry
    ; Each slot is 64 bytes
    mov rbx, rcx
    shl rbx, 6              ; RBX = slotIndex * 64
    lea rdi, [RawrXD_GPUBufferRegistry + rbx]
    
    ; Store buffer handle (offset 0)
    mov [rdi], rdx
    
    ; Store fence handle (offset 8)
    mov [rdi + 8], r8
    
    ; Clear upload complete flag (offset 16)
    mov QWORD PTR [rdi + 16], 0
    
    ; Store preparing slot index
    mov RawrXD_PreparingGPUSlot, rcx
    
    ; Memory barrier to ensure writes are visible
    sfence
    
    xor rax, rax            ; Return success
    jmp done
    
error_invalid_slot:
    mov rax, -1
    
done:
    pop rdi
    pop rbx
    ret
RawrXD_PrepareShadowGPUBuffer ENDP

; ----------------------------------------------------------------------------
; RawrXD_CommitGPUBufferSwap
;   Mark shadow GPU buffer as ready and trigger epoch rotation
; 
; Input:  RCX = slotIndex (1 or 2)
;         RDX = uploadEpoch (epoch when upload completed)
; Output: RAX = 0 on success, -1 on error
; ----------------------------------------------------------------------------
RawrXD_CommitGPUBufferSwap PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog
    
    ; Validate slot index
    cmp rcx, 1
    jb error_invalid_slot
    cmp rcx, 2
    ja error_invalid_slot
    
    ; Calculate slot offset
    mov rbx, rcx
    shl rbx, 6
    lea rdi, [RawrXD_GPUBufferRegistry + rbx]
    
    ; Set upload complete flag (offset 16)
    mov QWORD PTR [rdi + 16], 1
    
    ; Store assigned epoch (offset 24)
    mov [rdi + 24], rdx
    
    ; Memory barrier
    sfence
    
    ; Now the router can see this buffer is ready
    xor rax, rax
    jmp done
    
error_invalid_slot:
    mov rax, -1
    
done:
    pop rdi
    pop rbx
    ret
RawrXD_CommitGPUBufferSwap ENDP

; ----------------------------------------------------------------------------
; RawrXD_SwapGPUBuffer
;   Atomic swap of GPU buffer handles during epoch rotation
; 
; Input:  RCX = newSlotIndex (the shadow slot becoming active)
; Output: RAX = previous active slot index
; ----------------------------------------------------------------------------
RawrXD_SwapGPUBuffer PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Get current active slot
    mov rax, RawrXD_ActiveGPUSlot
    mov rbx, rcx                    ; RBX = new slot
    
    ; Atomic update of active slot
    ; Note: This is called from the router's epoch rotation, which already
    ; holds the epoch lock, so we don't need additional synchronization
    mov RawrXD_ActiveGPUSlot, rbx
    
    ; Memory barrier to ensure the swap is visible
    sfence
    
    ; Return previous active slot (RAX already has it)
    pop rbx
    ret
RawrXD_SwapGPUBuffer ENDP

; ----------------------------------------------------------------------------
; RawrXD_GetGPUBuffer
;   Get the current active GPU buffer handle (reader entry)
; 
; Input:  None
; Output: RAX = VulkanBuffer* handle, or 0 if none active
;         RDX = assigned epoch (for validation)
; ----------------------------------------------------------------------------
RawrXD_GetGPUBuffer PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog
    
    ; Get current active slot
    mov rbx, RawrXD_ActiveGPUSlot
    
    ; Calculate slot offset
    mov rdi, rbx
    shl rdi, 6
    lea rdi, [RawrXD_GPUBufferRegistry + rdi]
    
    ; Load buffer handle (offset 0)
    mov rax, [rdi]
    
    ; Load assigned epoch (offset 24)
    mov rdx, [rdi + 24]
    
    ; Memory barrier to ensure we see consistent state
    lfence
    
    pop rdi
    pop rbx
    ret
RawrXD_GetGPUBuffer ENDP

; ----------------------------------------------------------------------------
; RawrXD_ReleaseGPUBuffer
;   Release a GPU buffer reference (decrement reader count)
; 
; Input:  RCX = slotIndex
; Output: None
; ----------------------------------------------------------------------------
RawrXD_ReleaseGPUBuffer PROC FRAME
    ; Currently a placeholder - actual RCU cleanup happens in router
    ; This is called by inference threads when done with a buffer
    
    ; Memory barrier to ensure all reads complete before potential cleanup
    lfence
    
    ret
RawrXD_ReleaseGPUBuffer ENDP

; ============================================================================
; Integration Helpers
; ============================================================================

; ----------------------------------------------------------------------------
; RawrXD_GetGPUBufferForSlot
;   Get GPU buffer handle for a specific slot (used by router)
; 
; Input:  RCX = slotIndex (0-2)
; Output: RAX = VulkanBuffer* handle
; ----------------------------------------------------------------------------
RawrXD_GetGPUBufferForSlot PROC FRAME
    push rdi
    .pushreg rdi
    .endprolog
    
    ; Validate slot
    cmp rcx, 2
    ja invalid_slot
    
    ; Calculate offset
    mov rdi, rcx
    shl rdi, 6
    lea rdi, [RawrXD_GPUBufferRegistry + rdi]
    
    ; Load buffer handle
    mov rax, [rdi]
    jmp done
    
invalid_slot:
    xor rax, rax
    
done:
    pop rdi
    ret
RawrXD_GetGPUBufferForSlot ENDP

END
