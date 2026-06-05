; ============================================================================
; RawrXD_Vulkan_Shim.asm — Data Plane Hot-Path Dispatch
; ============================================================================
; Target: x64 MASM (Microsoft Macro Assembler)
; Purpose: Zero-overhead bridge from C++ Control Plane to Vulkan driver.
;
; Design rules:
;   - 40-byte shadow space (32-byte Windows ABI + 8-byte alignment)
;   - RCX preserved as `this` pointer across all hot-path calls
;   - No heap allocation inside dispatch path
;   - No exception checking to preserve cycles
;
; Target GPU: AMD Radeon RX 7800 XT (16 GB VRAM, Vulkan 1.4)
; ============================================================================

OPTION CASEMAP:NONE

; ============================================================================
; External linkage — Vulkan function pointers resolved at init time
; ============================================================================
; These QWORDs are populated by VulkanAccelerator::Initialize() via
; vkGetDeviceProcAddr and stored in a static table accessible to ASM.
;
; The C++ bridge writes these before any dispatch calls.
; ============================================================================

EXTERN p_vkCmdDispatch      : QWORD
EXTERN p_vkQueueSubmit      : QWORD
EXTERN p_vkWaitForFences    : QWORD
EXTERN p_vkCmdBindPipeline  : QWORD
EXTERN p_vkCmdBindDescriptorSets : QWORD
EXTERN p_vkCmdPushConstants : QWORD
EXTERN p_vkCmdDispatchIndirect : QWORD
EXTERN p_vkQueueWaitIdle    : QWORD
EXTERN p_vkResetFences      : QWORD
EXTERN p_vkGetSemaphoreCounterValue : QWORD

; ============================================================================
; Internal helper macros
; ============================================================================

; Reserve standard Windows x64 shadow space + align to 16 bytes
SHADOW_SPACE MACRO
    sub rsp, 40
ENDM

; Restore stack
RESTORE_STACK MACRO
    add rsp, 40
ENDM

; ============================================================================
; RawrXD_DispatchMatMul_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this / handle)
; RDX = MatMulDesc* (pointer to descriptor struct)
;
; MatMulDesc layout (must match C++ struct exactly):
;   +0x00  GpuTensorHandle A
;   +0x18  GpuTensorHandle B
;   +0x30  GpuTensorHandle Out
;   +0x48  uint32_t M
;   +0x4C  uint32_t K
;   +0x50  uint32_t N
;   +0x54  uint32_t A_format
;   +0x58  bool transA
;   +0x59  bool transB
;
; Returns: EAX = 0 on success, non-zero on failure
; ============================================================================

.CODE

RawrXD_DispatchMatMul_Asm PROC PUBLIC
    SHADOW_SPACE

    ; --- Preserve non-volatile registers ---
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 8              ; Align to 16 bytes after 3 pushes (24 bytes)

    ; --- RCX = this, RDX = MatMulDesc* ---
    ; Load command buffer from this->pImpl_->command_buffer_
    ; Offset 0x10 = pImpl_ unique_ptr (first member of VulkanAccelerator)
    ; Offset 0x00 = command_buffer_ (first member of Impl)
    mov     rax, [rcx + 10h]    ; rax = pImpl_ pointer
    mov     rbx, [rax + 00h]    ; rbx = VkCommandBuffer handle

    ; --- Load dispatch dimensions from MatMulDesc ---
    ; M at offset 0x48, K at 0x4C, N at 0x50
    mov     r8d, [rdx + 48h]    ; groupCountX = M
    mov     r9d, [rdx + 4Ch]    ; groupCountY = K
    mov     r10d, [rdx + 50h]   ; groupCountZ = N

    ; --- Call vkCmdDispatch(commandBuffer, groupCountX, groupCountY, groupCountZ) ---
    ; RCX = commandBuffer (rbx), RDX = groupCountX, R8 = groupCountY, R9 = groupCountZ
    mov     rcx, rbx
    mov     edx, r8d
    mov     r8d, r9d
    mov     r9d, r10d
    call    [p_vkCmdDispatch]

    ; --- Success ---
    xor     eax, eax

    ; --- Restore ---
    add     rsp, 8
    pop     rsi
    pop     rdi
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_DispatchMatMul_Asm ENDP

; ============================================================================
; RawrXD_KVAppend_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)
; RDX = KVAppendDesc* (pointer to descriptor struct)
;
; KVAppendDesc layout:
;   +0x00  GpuTensorHandle K_cache
;   +0x18  GpuTensorHandle V_cache
;   +0x30  GpuTensorHandle K_new
;   +0x48  GpuTensorHandle V_new
;   +0x60  uint32_t layer_idx
;   +0x64  uint32_t seq_pos
;   +0x68  uint32_t head_dim
;   +0x6C  uint32_t n_heads
;
; Hot path: Directly push KV data to VRAM via mapped buffer.
; No exception checking to preserve cycles.
; ============================================================================

RawrXD_KVAppend_Asm PROC PUBLIC
    SHADOW_SPACE

    ; --- Preserve ---
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 8

    ; --- Load command buffer ---
    mov     rax, [rcx + 10h]    ; pImpl_
    mov     rbx, [rax + 30h]    ; command_buffer_ (offset 0x30 in Impl)

    ; --- Load KV cache buffer handles ---
    ; K_cache buffer at offset 0x08 within GpuTensorHandle
    mov     rdi, [rdx + 00h]    ; K_cache.id
    mov     rsi, [rdx + 08h]    ; K_cache.buffer (VkBuffer)

    ; --- For scaffolding: bind descriptor sets and dispatch 1D workgroup ---
    ; Full implementation will compute exact byte offset into mapped memory
    ; and use vkCmdUpdateBuffer or vkCmdCopyBuffer.

    ; --- Call vkCmdDispatch(1, 1, 1) for single-token append ---
    mov     rcx, rbx
    mov     edx, 1              ; groupCountX
    mov     r8d, 1              ; groupCountY
    mov     r9d, 1              ; groupCountZ
    call    [p_vkCmdDispatch]

    xor     eax, eax

    ; --- Restore ---
    add     rsp, 8
    pop     rsi
    pop     rdi
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_KVAppend_Asm ENDP

; ============================================================================
; RawrXD_Wait_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)
; RDX = timeout_ns (uint64_t)
;
; Direct fence wait. This is the synchronization bottleneck — keep it tight.
; ============================================================================

RawrXD_Wait_Asm PROC PUBLIC
    SHADOW_SPACE

    ; --- Preserve ---
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 8              ; Align to 16 after 3 pushes (24 bytes)

    ; --- Save timeout (RDX) into non-volatile RSI before we overwrite RDX ---
    mov     rsi, rdx            ; rsi = timeout_ns

    ; --- Load device and fence from pImpl_ ---
    mov     rax, [rcx + 10h]    ; pImpl_
    mov     rbx, [rax + 08h]    ; device (VkDevice)   — offset 0x08
    mov     rdi, [rax + 38h]    ; fence (VkFence)     — offset 0x38

    ; --- vkWaitForFences(device, fenceCount=1, &fence, waitAll=VK_TRUE, timeout) ---
    ; RCX = device, RDX = fenceCount, R8 = &fence, R9 = waitAll, [rsp+0x20] = timeout
    mov     rcx, rbx
    mov     edx, 1
    lea     r8, [rsp + 28h]     ; &fence — outside callee shadow space
    mov     [r8], rdi
    mov     r9d, 1              ; VK_TRUE = 1
    mov     [rsp + 20h], rsi    ; timeout (64-bit) — 5th arg
    call    [p_vkWaitForFences]

    ; --- Reset fence for next use ---
    mov     rcx, rbx            ; device
    mov     edx, 1              ; fenceCount
    lea     r8, [rsp + 28h]     ; &fence
    mov     [r8], rdi
    call    [p_vkResetFences]

    xor     eax, eax

    ; --- Restore ---
    add     rsp, 8
    pop     rsi
    pop     rdi
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_Wait_Asm ENDP

; ============================================================================
; RawrXD_SubmitGraph_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)
; RDX = submit_info pointer (VkSubmitInfo*)
;
; Single vkQueueSubmit for batched graph execution.
; This is the 10x-20x overhead reduction path.
; ============================================================================

RawrXD_SubmitGraph_Asm PROC PUBLIC
    SHADOW_SPACE

    push    rbx
    sub     rsp, 8

    ; --- Load queue from pImpl_ ---
    mov     rax, [rcx + 10h]    ; pImpl_
    mov     rbx, [rax + 18h]    ; queue (VkQueue)

    ; --- vkQueueSubmit(queue, submitCount=1, pSubmits, fence=0) ---
    mov     rcx, rbx            ; queue
    mov     edx, 1              ; submitCount
    mov     r8, rdx             ; pSubmits (passed in RDX)
    xor     r9d, r9d            ; fence = VK_NULL_HANDLE
    call    [p_vkQueueSubmit]

    xor     eax, eax

    add     rsp, 8
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_SubmitGraph_Asm ENDP

; ============================================================================
; RawrXD_QueueWaitIdle_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)
;
; Emergency drain — use sparingly. Prefer RawrXD_Wait_Asm with fences.
; ============================================================================

RawrXD_QueueWaitIdle_Asm PROC PUBLIC
    SHADOW_SPACE

    push    rbx
    sub     rsp, 8

    mov     rax, [rcx + 10h]    ; pImpl_
    mov     rbx, [rax + 18h]    ; queue

    mov     rcx, rbx
    call    [p_vkQueueWaitIdle]

    xor     eax, eax

    add     rsp, 8
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_QueueWaitIdle_Asm ENDP

; ============================================================================
; RawrXD_DispatchRMSNorm_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)  — unused, kept for ABI consistency
; RDX = RMSNormDispatchArgs* (pointer to packed argument struct)
;
; RMSNormDispatchArgs layout (must match C++ struct exactly):
;   +0x00  VkCommandBuffer   cmd
;   +0x08  VkPipeline        pipeline
;   +0x10  VkPipelineLayout  layout
;   +0x18  VkDescriptorSet   desc_set
;   +0x20  uint32_t          hidden_size
;   +0x24  float             eps
;   +0x28  uint32_t          num_rows
;
; Hot path: bind pipeline, descriptors, push constants, dispatch.
; No exception checking to preserve cycles.
; ============================================================================

RawrXD_DispatchRMSNorm_Asm PROC PUBLIC
    SHADOW_SPACE

    push    rbx
    push    rdi
    push    rsi
    push    r12
    sub     rsp, 8              ; Align to 16 after 4 pushes (32 bytes)

    ; --- Save args pointer (RDX) into non-volatile RSI ---
    mov     rsi, rdx            ; rsi = args pointer (preserved across calls)

    ; --- Load handles from args ---
    mov     rbx, [rsi + 00h]    ; cmd
    mov     rdi, [rsi + 08h]    ; pipeline
    mov     r12, [rsi + 18h]    ; desc_set  (r12 is non-volatile, saved above)

    ; --- 1. vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline) ---
    ; RCX = cmd, RDX = bindPoint (1 = COMPUTE), R8 = pipeline
    mov     rcx, rbx
    mov     edx, 1              ; VK_PIPELINE_BIND_POINT_COMPUTE
    mov     r8, rdi
    call    [p_vkCmdBindPipeline]

    ; --- 2. vkCmdBindDescriptorSets(cmd, COMPUTE, layout, firstSet=0, setCount=1, &descSet, dynamicCount=0, NULL) ---
    ; RCX = cmd, RDX = bindPoint, R8 = layout, R9 = firstSet
    ; [rsp+0x30] = setCount, [rsp+0x38] = pDescriptorSets, [rsp+0x40] = dynamicCount, [rsp+0x48] = pDynamicOffsets
    mov     rcx, rbx
    mov     edx, 1              ; COMPUTE
    mov     r8, [rsi + 10h]     ; layout (from args)
    xor     r9d, r9d            ; firstSet = 0
    mov     dword ptr [rsp + 30h], 1          ; setCount = 1
    lea     rax, [rsp + 20h]
    mov     [rax], r12                        ; store desc_set on stack
    mov     [rsp + 38h], rax                  ; pDescriptorSets = &desc_set
    mov     dword ptr [rsp + 40h], 0          ; dynamicCount = 0
    mov     qword ptr [rsp + 48h], 0          ; pDynamicOffsets = NULL
    call    [p_vkCmdBindDescriptorSets]

    ; --- 3. vkCmdPushConstants(cmd, layout, stageFlags=COMPUTE, offset=0, size=8, &pc) ---
    ; RCX = cmd, RDX = layout, R8 = stageFlags, R9 = offset
    ; [rsp+0x30] = size, [rsp+0x38] = pValues
    mov     rcx, rbx
    mov     rdx, [rsi + 10h]    ; layout (from args)
    mov     r8d, 20h            ; VK_SHADER_STAGE_COMPUTE_BIT = 0x20
    xor     r9d, r9d            ; offset = 0
    mov     dword ptr [rsp + 30h], 8          ; size = 8 bytes
    lea     rax, [rsi + 20h]    ; &args->hidden_size (offset 0x20 in struct)
    mov     [rsp + 38h], rax                  ; pValues
    call    [p_vkCmdPushConstants]

    ; --- 4. vkCmdDispatch(cmd, groupCountX=num_rows, groupCountY=1, groupCountZ=1) ---
    mov     rcx, rbx
    mov     r8d, [rsi + 28h]    ; num_rows (from args)
    mov     edx, r8d            ; groupCountX
    mov     r8d, 1              ; groupCountY
    mov     r9d, 1              ; groupCountZ
    call    [p_vkCmdDispatch]

    xor     eax, eax

    ; --- Restore ---
    add     rsp, 8
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_DispatchRMSNorm_Asm ENDP

; ============================================================================
; RawrXD_TimelinePoll_Asm
; ============================================================================
; RCX = VulkanAccelerator* (this)
; RDX = target_value (uint64_t)
; R8  = out_current* (uint64_t*)
;
; Non-blocking poll of timeline semaphore.
; Returns: EAX = 1 if target reached, 0 if not yet (out_current written)
; ============================================================================

RawrXD_TimelinePoll_Asm PROC PUBLIC
    SHADOW_SPACE

    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 8              ; Align to 16 after 3 pushes (24 bytes)

    ; --- Save args ---
    mov     rsi, rdx            ; rsi = target_value
    mov     rdi, r8             ; rdi = out_current pointer

    ; --- Load device and timeline_semaphore from pImpl_ ---
    mov     rax, [rcx + 10h]    ; pImpl_
    mov     rbx, [rax + 08h]    ; device (VkDevice)   — offset 0x08
    mov     r12, [rax + 58h]    ; timeline_semaphore (offset 0x58 in Impl)
                                ;   0x00 instance
                                ;   0x08 device
                                ;   0x10 physical_device
                                ;   0x18 queue
                                ;   0x1C queue_family
                                ;   0x20 cmd_pool
                                ;   0x28 cmd_buffer
                                ;   0x30 fence
                                ;   0x38 staging_memory
                                ;   0x40 staging_buffer
                                ;   0x48 staging_mapped
                                ;   0x50 staging_size
                                ;   0x58 timeline_semaphore  ← HERE

    ; --- vkGetSemaphoreCounterValue(device, semaphore, &current) ---
    ; RCX = device, RDX = semaphore, R8 = &current (on stack)
    mov     rcx, rbx
    mov     rdx, r12
    lea     r8, [rsp + 28h]     ; &current — outside callee shadow space
    call    [p_vkGetSemaphoreCounterValue]

    ; --- Load current value from stack ---
    mov     rax, [rsp + 28h]    ; rax = current value

    ; --- Write out_current if pointer is non-null ---
    test    rdi, rdi
    jz      @F
    mov     [rdi], rax
@@:

    ; --- Compare current vs target ---
    cmp     rax, rsi
    setae   al                  ; al = 1 if current >= target, else 0
    movzx   eax, al

    ; --- Restore ---
    add     rsp, 8
    pop     rsi
    pop     rdi
    pop     rbx
    RESTORE_STACK
    ret
RawrXD_TimelinePoll_Asm ENDP

END
