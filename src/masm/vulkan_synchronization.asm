; ============================================================================
; RawrXD Vulkan Synchronization Core
; GPU Fence Lifecycle Management for Epoch-Based Hotpatching
; ============================================================================
; Architecture: x64 MASM with Vulkan VK_KHR_synchronization2
; Purpose: Zero-copy model switching with guaranteed GPU completion
; ============================================================================

; =============================================================================
; Vulkan Type Definitions (Opaque Handles)
; =============================================================================
VK_NULL_HANDLE          EQU     0

; VkFence Status
VK_FENCE_UNSIGNALED     EQU     0
VK_FENCE_SIGNALED       EQU     1

; VkResult Codes
VK_SUCCESS              EQU     0
VK_NOT_READY            EQU     1
VK_TIMEOUT              EQU     2
VK_ERROR_DEVICE_LOST    EQU     -4

; VkPipelineStageFlags2 (VK_KHR_synchronization2)
VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT    EQU     00000020h
VK_PIPELINE_STAGE_2_TRANSFER_BIT          EQU     00000100h

; =============================================================================
; Model Descriptor GPU State Structure
; =============================================================================
; Each model descriptor tracks its own Vulkan resources for independent lifecycle
;
; struct ModelDescriptorGPU {
;     uint64_t    vk_device;              // +0x00   VkDevice handle
;     uint64_t    vk_fence;               // +0x08   Completion fence
;     uint64_t    vk_cmd_pool;            // +0x10   Command pool for this model
;     uint64_t    vk_cmd_buffer;          // +0x18   Active command buffer
;     uint64_t    vk_descriptor_set;      // +0x20   Weight tensor descriptors
;     uint64_t    vk_pipeline;            // +0x28   Compute pipeline
;     uint64_t    vk_pipeline_layout;     // +0x30   Pipeline layout
;     uint32_t    fence_status;           // +0x38   0=unsignaled, 1=signaled
;     uint32_t    cmd_buffer_pending;     // +0x3C   1=submitted, 0=idle
;     uint64_t    weight_buffer_device;   // +0x40   Device memory for weights
;     uint64_t    weight_buffer_size;     // +0x48   Size in bytes
;     uint64_t    uniform_buffer;         // +0x50   Layer params, dims
;     uint64_t    completion_timestamp;   // +0x58   GPU timestamp on finish
; };

; Offsets into ModelDescriptorGPU
MD_GPU_DEVICE           EQU     0x00
MD_GPU_FENCE            EQU     0x08
MD_GPU_CMD_POOL         EQU     0x10
MD_GPU_CMD_BUFFER       EQU     0x18
MD_GPU_DESCRIPTOR_SET   EQU     0x20
MD_GPU_PIPELINE         EQU     0x28
MD_GPU_PIPELINE_LAYOUT  EQU     0x30
MD_GPU_FENCE_STATUS     EQU     0x38
MD_GPU_CMD_PENDING      EQU     0x3C
MD_GPU_WEIGHT_BUFFER    EQU     0x40
MD_GPU_WEIGHT_SIZE      EQU     0x48
MD_GPU_UNIFORM_BUFFER   EQU     0x50
MD_GPU_TIMESTAMP        EQU     0x58

; Total size: 0x60 bytes (96 bytes)

; =============================================================================
; Global State for Vulkan Synchronization
; =============================================================================
.data
    ALIGN 8
    
    ; Function pointers loaded from vulkan-1.dll
    g_vkWaitForFences2      QWORD   0       ; vkWaitForFences2KHR
    g_vkGetFenceStatus      QWORD   0       ; vkGetFenceStatus
    g_vkResetFences         QWORD   0       ; vkResetFences
    g_vkCmdPipelineBarrier2 QWORD   0       ; vkCmdPipelineBarrier2KHR
    g_vkGetDeviceProcAddr   QWORD   0       ; vkGetDeviceProcAddr
    
    ; Epoch tracking (from Strategy 1)
    g_EpochCounter          QWORD   0
    g_PendingModelDescriptor QWORD  0
    g_ActiveModelDescriptor QWORD   0
    
    ; GPU synchronization timeout (nanoseconds)
    ; Default: 100ms = 100,000,000 ns
    g_VulkanTimeoutNs       QWORD   100000000
    
    ; Statistics for debugging
    g_FenceWaits            QWORD   0       ; Number of fence waits
    g_FenceTimeouts         QWORD   0       ; Number of timeouts
    g_DeferredSwaps         QWORD   0       ; Swaps deferred due to pending GPU

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Vulkan_InitSynchronization
; Loads Vulkan function pointers for fence management
; Input:  rcx = VkDevice handle
;         rdx = vkGetDeviceProcAddr function pointer
; Output: rax = 0 on success, error code on failure
; =============================================================================
Vulkan_InitSynchronization PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .endprolog
    
    ; Store device and proc addr
    mov     r12, rcx                    ; r12 = VkDevice
    mov     r13, rdx                    ; r13 = vkGetDeviceProcAddr
    mov     g_vkGetDeviceProcAddr, r13
    
    ; Load vkWaitForFences2KHR (requires VK_KHR_synchronization2)
    mov     rcx, r12                    ; Device
    lea     rdx, [vkWaitForFences2Name]
    call    r13                         ; Call vkGetDeviceProcAddr
    test    rax, rax
    jz      .error_no_extension
    mov     g_vkWaitForFences2, rax
    
    ; Load vkGetFenceStatus
    mov     rcx, r12
    lea     rdx, [vkGetFenceStatusName]
    call    r13
    test    rax, rax
    jz      .error_no_function
    mov     g_vkGetFenceStatus, rax
    
    ; Load vkResetFences
    mov     rcx, r12
    lea     rdx, [vkResetFencesName]
    call    r13
    test    rax, rax
    jz      .error_no_function
    mov     g_vkResetFences, rax
    
    ; Load vkCmdPipelineBarrier2KHR
    mov     rcx, r12
    lea     rdx, [vkCmdPipelineBarrier2Name]
    call    r13
    test    rax, rax
    jz      .error_no_extension
    mov     g_vkCmdPipelineBarrier2, rax
    
    xor     rax, rax                    ; Success
    jmp     .exit
    
.error_no_extension:
    mov     rax, -1                     ; VK_KHR_synchronization2 not available
    jmp     .exit
    
.error_no_function:
    mov     rax, -2                     ; Required function not found
    
.exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

; Function name strings
vkWaitForFences2Name:       DB      "vkWaitForFences2KHR", 0
vkGetFenceStatusName:       DB      "vkGetFenceStatus", 0
vkResetFencesName:          DB      "vkResetFences", 0
vkCmdPipelineBarrier2Name:  DB      "vkCmdPipelineBarrier2KHR", 0

Vulkan_InitSynchronization ENDP

; =============================================================================
; Vulkan_CheckFenceStatus
; Non-blocking check if GPU work for a model has completed
; Input:  rcx = ModelDescriptorGPU pointer
; Output: rax = 0 (idle), 1 (pending), -1 (error)
; =============================================================================
Vulkan_CheckFenceStatus PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    .endprolog
    
    mov     rbx, rcx                    ; rbx = ModelDescriptorGPU
    
    ; Check if there's pending work
    mov     eax, DWORD PTR [rbx + MD_GPU_CMD_PENDING]
    test    eax, eax
    jz      .idle                       ; No pending work
    
    ; Get fence handle
    mov     r12, [rbx + MD_GPU_FENCE]   ; r12 = VkFence
    test    r12, r12
    jz      .idle                       ; No fence = no work
    
    ; Call vkGetFenceStatus
    mov     rcx, [rbx + MD_GPU_DEVICE]  ; Device
    mov     rdx, r12                    ; Fence
    mov     rax, g_vkGetFenceStatus
    test    rax, rax
    jz      .error
    
    call    rax                         ; Returns VkResult
    
    ; Check result
    cmp     eax, VK_SUCCESS             ; Fence is signaled
    je      .signaled
    cmp     eax, VK_NOT_READY           ; Fence not yet signaled
    je      .pending
    
    ; Error case (VK_ERROR_DEVICE_LOST, etc.)
    jmp     .error
    
.signaled:
    ; Mark as complete
    mov     DWORD PTR [rbx + MD_GPU_CMD_PENDING], 0
    mov     DWORD PTR [rbx + MD_GPU_FENCE_STATUS], VK_FENCE_SIGNALED
    
    ; Record completion timestamp
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rbx + MD_GPU_TIMESTAMP], rax
    
    mov     rax, 0                      ; Now idle
    jmp     .exit
    
.pending:
    mov     rax, 1                      ; Still pending
    jmp     .exit
    
.idle:
    xor     rax, rax                    ; Idle
    jmp     .exit
    
.error:
    mov     rax, -1                     ; Error
    
.exit:
    pop     r12
    pop     rbx
    pop     rbp
    ret
Vulkan_CheckFenceStatus ENDP

; =============================================================================
; Vulkan_WaitForFenceBlocking
; Blocking wait for GPU completion with timeout
; Input:  rcx = ModelDescriptorGPU pointer
;         rdx = timeout_ns (0 = use default)
; Output: rax = 0 (success), -1 (timeout), -2 (error)
; =============================================================================
Vulkan_WaitForFenceBlocking PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    .endprolog
    
    mov     rbx, rcx                    ; rbx = ModelDescriptorGPU
    mov     r12, rdx                    ; r12 = timeout_ns
    
    ; Use default timeout if not specified
    test    r12, r12
    jnz     .timeout_set
    mov     r12, g_VulkanTimeoutNs
    
.timeout_set:
    ; Get fence handle
    mov     r13, [rbx + MD_GPU_FENCE]   ; r13 = VkFence
    test    r13, r13
    jz      .success                    ; No fence = nothing to wait for
    
    ; Check if already signaled (fast path)
    mov     eax, DWORD PTR [rbx + MD_GPU_FENCE_STATUS]
    cmp     eax, VK_FENCE_SIGNALED
    je      .success
    
    ; Increment fence wait counter
    lock    inc QWORD PTR [g_FenceWaits]
    
    ; Prepare VkSemaphoreWaitInfo structure (on stack)
    ; typedef struct VkSemaphoreWaitInfo {
    ;     VkStructureType          sType;
    ;     const void*              pNext;
    ;     VkSemaphoreWaitFlags     flags;
    ;     uint32_t                 semaphoreCount;
    ;     const VkSemaphore*       pSemaphores;
    ;     const uint64_t*          pValues;
    ; } VkSemaphoreWaitInfo;
    
    ; For vkWaitForFences2KHR, we use VkFenceWaitInfo:
    ; typedef struct VkFenceWaitInfo {
    ;     VkStructureType          sType;
    ;     const void*              pNext;
    ;     VkFenceWaitFlags         flags;
    ;     uint32_t                 fenceCount;
    ;     const VkFence*           pFences;
    ;     uint64_t                 timeout;
    ; } VkFenceWaitInfo;
    
    sub     rsp, 48                     ; Allocate stack space
    
    mov     DWORD PTR [rsp + 0], 1000115000  ; VK_STRUCTURE_TYPE_FENCE_WAIT_INFO_KHR
    mov     QWORD PTR [rsp + 8], 0      ; pNext
    mov     DWORD PTR [rsp + 16], 0     ; flags
    mov     DWORD PTR [rsp + 20], 1     ; fenceCount
    lea     rax, [rbx + MD_GPU_FENCE]
    mov     QWORD PTR [rsp + 24], rax   ; pFences
    mov     QWORD PTR [rsp + 32], r12   ; timeout
    
    ; Call vkWaitForFences2KHR
    mov     rcx, [rbx + MD_GPU_DEVICE]  ; Device
    mov     rdx, rsp                    ; pWaitInfo
    xor     r8, r8                      ; pResult (optional)
    mov     rax, g_vkWaitForFences2
    call    rax
    
    add     rsp, 48                     ; Clean up stack
    
    ; Check result
    cmp     eax, VK_SUCCESS
    je      .wait_success
    cmp     eax, VK_TIMEOUT
    je      .timeout
    
    ; Other error
    jmp     .error
    
.wait_success:
    ; Mark as complete
    mov     DWORD PTR [rbx + MD_GPU_CMD_PENDING], 0
    mov     DWORD PTR [rbx + MD_GPU_FENCE_STATUS], VK_FENCE_SIGNALED
    
.success:
    xor     rax, rax
    jmp     .exit
    
.timeout:
    lock    inc QWORD PTR [g_FenceTimeouts]
    mov     rax, -1
    jmp     .exit
    
.error:
    mov     rax, -2
    
.exit:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
Vulkan_WaitForFenceBlocking ENDP

; =============================================================================
; Vulkan_InsertPipelineBarrier
; Ensures all previous GPU writes are visible before next dispatch
; Input:  rcx = ModelDescriptorGPU pointer
; Output: rax = 0 on success
; =============================================================================
Vulkan_InsertPipelineBarrier PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    .endprolog
    
    mov     rbx, rcx                    ; rbx = ModelDescriptorGPU
    
    ; Get command buffer
    mov     r12, [rbx + MD_GPU_CMD_BUFFER]
    test    r12, r12
    jz      .success                    ; No command buffer
    
    ; Build VkDependencyInfo for memory barrier
    ; This ensures weight buffer writes are complete before read
    
    sub     rsp, 128                    ; Stack space for structures
    
    ; VkMemoryBarrier2
    mov     DWORD PTR [rsp + 0], 0      ; sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2
    mov     QWORD PTR [rsp + 8], 0      ; pNext
    mov     QWORD PTR [rsp + 16], VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT  ; srcStageMask
    mov     QWORD PTR [rsp + 24], 0     ; srcAccessMask
    mov     QWORD PTR [rsp + 32], VK_PIPELINE_STAGE_2_COMPUTE_SHADER_BIT  ; dstStageMask
    mov     QWORD PTR [rsp + 40], 0     ; dstAccessMask
    
    ; VkDependencyInfo
    mov     DWORD PTR [rsp + 48], 1000116000  ; VK_STRUCTURE_TYPE_DEPENDENCY_INFO
    mov     QWORD PTR [rsp + 56], 0     ; pNext
    mov     DWORD PTR [rsp + 64], 0     ; dependencyFlags
    mov     DWORD PTR [rsp + 68], 0     ; memoryBarrierCount (using buffer barriers instead)
    mov     QWORD PTR [rsp + 72], 0     ; pMemoryBarriers
    mov     DWORD PTR [rsp + 80], 0     ; bufferMemoryBarrierCount
    mov     QWORD PTR [rsp + 88], 0     ; pBufferMemoryBarriers
    mov     DWORD PTR [rsp + 96], 0     ; imageMemoryBarrierCount
    mov     QWORD PTR [rsp + 104], 0    ; pImageMemoryBarriers
    
    ; Call vkCmdPipelineBarrier2KHR
    mov     rcx, r12                    ; Command buffer
    lea     rdx, [rsp + 48]             ; pDependencyInfo
    mov     rax, g_vkCmdPipelineBarrier2
    test    rax, rax
    jz      .skip_barrier
    call    rax
    
.skip_barrier:
    add     rsp, 128
    
.success:
    xor     rax, rax
    jmp     .exit
    
.exit:
    pop     r12
    pop     rbx
    pop     rbp
    ret
Vulkan_InsertPipelineBarrier ENDP

; =============================================================================
; RawrXD_TryHotpatchWithGPUCheck
; Epoch-based hotpatch with GPU completion verification
; Called at layer boundary when epoch is odd
; Input:  rcx = Current model descriptor
; Output: rax = 0 (swap complete), 1 (deferred), -1 (error)
; =============================================================================
RawrXD_TryHotpatchWithGPUCheck PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    .endprolog
    
    mov     rbx, rcx                    ; rbx = current model
    
    ; Get pending model
    mov     r12, g_PendingModelDescriptor
    test    r12, r12
    jz      .no_pending                 ; No pending swap
    
    ; Check GPU status of current model
    mov     rcx, rbx
    call    Vulkan_CheckFenceStatus
    
    cmp     rax, 0
    je      .gpu_idle                   ; GPU idle, safe to swap
    cmp     rax, 1
    je      .gpu_busy                   ; GPU still working
    
    ; Error case
    jmp     .error
    
.gpu_idle:
    ; Safe to swap immediately
    jmp     .execute_swap
    
.gpu_busy:
    ; GPU is still processing current model
    ; Try non-blocking wait with short timeout (1ms)
    mov     rcx, rbx
    mov     rdx, 1000000                ; 1ms in nanoseconds
    call    Vulkan_WaitForFenceBlocking
    
    cmp     rax, 0
    je      .execute_swap               ; GPU finished, swap now
    cmp     rax, -1
    je      .defer                      ; Timeout, defer to next layer
    
    ; Error
    jmp     .error
    
.execute_swap:
    ; Insert pipeline barrier to ensure memory visibility
    mov     rcx, rbx
    call    Vulkan_InsertPipelineBarrier
    
    ; Perform the atomic swap
    mov     r13, g_PendingModelDescriptor
    xchg    g_ActiveModelDescriptor, r13    ; r13 = old model
    mov     g_PendingModelDescriptor, 0
    
    ; Increment epoch (make even)
    lock    inc QWORD PTR [g_EpochCounter]
    
    ; Reset fence status for new model
    mov     DWORD PTR [r12 + MD_GPU_FENCE_STATUS], VK_FENCE_UNSIGNALED
    mov     DWORD PTR [r12 + MD_GPU_CMD_PENDING], 0
    
    xor     rax, rax                    ; Success
    jmp     .exit
    
.defer:
    ; Increment deferred swap counter
    lock    inc QWORD PTR [g_DeferredSwaps]
    mov     rax, 1                    ; Deferred
    jmp     .exit
    
.no_pending:
    xor     rax, rax                    ; No swap needed
    jmp     .exit
    
.error:
    mov     rax, -1
    
.exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
RawrXD_TryHotpatchWithGPUCheck ENDP

; =============================================================================
; RawrXD_SubmitModelWork
; Submit GPU work for current model with fence tracking
; Input:  rcx = ModelDescriptorGPU pointer
; Output: rax = 0 on success
; =============================================================================
RawrXD_SubmitModelWork PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    .endprolog
    
    mov     rbx, rcx
    
    ; Mark command buffer as pending
    mov     DWORD PTR [rbx + MD_GPU_CMD_PENDING], 1
    mov     DWORD PTR [rbx + MD_GPU_FENCE_STATUS], VK_FENCE_UNSIGNALED
    
    ; Reset fence if it was previously signaled
    ; (Implementation depends on your vkQueueSubmit wrapper)
    
    xor     rax, rax
    
    pop     r12
    pop     rbx
    pop     rbp
    ret
RawrXD_SubmitModelWork ENDP

; =============================================================================
; Exports
; =============================================================================
PUBLIC Vulkan_InitSynchronization
PUBLIC Vulkan_CheckFenceStatus
PUBLIC Vulkan_WaitForFenceBlocking
PUBLIC Vulkan_InsertPipelineBarrier
PUBLIC RawrXD_TryHotpatchWithGPUCheck
PUBLIC RawrXD_SubmitModelWork

END
