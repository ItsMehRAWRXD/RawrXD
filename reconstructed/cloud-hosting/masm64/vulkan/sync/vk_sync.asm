; ============================================================================
; Vulkan Synchronization Primitives (MASM x64)
; ============================================================================
; Implements fences and semaphores for GPU synchronization
; Replaces vkCreateFence, vkWaitForFences, vkResetFences, etc.
; ============================================================================

.code

INCLUDE vulkan_types.inc

; ============================================================================
; External Windows API functions
; ============================================================================
EXTERN CreateEventA:PROC
EXTERN SetEvent:PROC
EXTERN ResetEvent:PROC
EXTERN WaitForSingleObject:PROC
EXTERN CloseHandle:PROC

; ============================================================================
; Constants
; ============================================================================
INFINITE EQU 0FFFFFFFFh
WAIT_OBJECT_0 EQU 0

; ============================================================================
; Synchronization tracking
; ============================================================================
.data
    g_fences        QWORD 32 DUP(0)      ; Fence handles (Windows events)
    g_fenceStates   DWORD 32 DUP(0)      ; Fence states (0=unsignaled, 1=signaled)
    g_fenceCount    DWORD 0
    g_nextFenceId   QWORD 600h

; ============================================================================
; vkCreateFenceMASM - Create fence
; 
; Parameters:
;   RCX = VkDevice
;   RDX = pointer to VkFenceCreateInfo
;   R8  = allocator (can be NULL)
;   R9  = pointer to VkFence handle
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkCreateFenceMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    
    ; Validate inputs
    test rcx, rcx
    jz fence_error
    test rdx, rdx
    jz fence_error
    test r9, r9
    jz fence_error
    
    ; Check if we have space
    mov eax, g_fenceCount
    cmp eax, 32
    jae fence_error_full
    
    ; Get flags to check if should be signaled
    mov ebx, [rdx + VkFenceCreateInfo.flags]
    
    ; Create Windows event for fence
    xor ecx, ecx        ; lpEventAttributes = NULL
    mov edx, 1          ; bManualReset = TRUE
    
    ; Initial state based on flags
    test ebx, VK_FENCE_CREATE_SIGNALED_BIT
    jz fence_create_unsignaled
    mov r8d, 1          ; bInitialState = TRUE (signaled)
    jmp fence_create_event
    
fence_create_unsignaled:
    xor r8d, r8d        ; bInitialState = FALSE (unsignaled)
    
fence_create_event:
    xor r9d, r9d        ; lpName = NULL
    call CreateEventA
    test rax, rax
    jz fence_error
    
    ; Find free slot
    xor ecx, ecx
    lea rdi, g_fences
    
fence_find_slot:
    cmp ecx, 32
    jae fence_error_full
    
    mov r8, [rdi + rcx*8]
    test r8, r8
    jz fence_found_slot
    
    inc ecx
    jmp fence_find_slot
    
fence_found_slot:
    ; Store event handle
    mov [rdi + rcx*8], rax
    
    ; Store initial state
    lea rdi, g_fenceStates
    test ebx, VK_FENCE_CREATE_SIGNALED_BIT
    jz fence_store_unsignaled
    mov DWORD PTR [rdi + rcx*4], 1
    jmp fence_store_handle
    
fence_store_unsignaled:
    mov DWORD PTR [rdi + rcx*4], 0
    
fence_store_handle:
    ; Create and return fence handle
    mov rax, g_nextFenceId
    inc g_nextFenceId
    
    ; Return handle (encode slot in lower bits)
    shl rax, 8
    or rax, rcx
    mov rbx, [rbp+40h]  ; Get r9 from original call
    mov [rbx], rax
    
    ; Increment count
    inc g_fenceCount
    
    xor eax, eax    ; VK_SUCCESS
    jmp fence_cleanup
    
fence_error_full:
    mov eax, VK_ERROR_OUT_OF_HOST_MEMORY
    jmp fence_cleanup
    
fence_error:
    mov eax, VK_ERROR_INITIALIZATION_FAILED
    
fence_cleanup:
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkCreateFenceMASM ENDP

; ============================================================================
; vkWaitForFencesMASM - Wait for fences to be signaled
; 
; Parameters:
;   RCX = VkDevice
;   RDX = fenceCount
;   R8  = pointer to VkFence array
;   R9  = waitAll (VkBool32)
;   [rbp+48] = timeout (uint64_t nanoseconds)
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkWaitForFencesMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    push rsi
    
    ; Validate inputs
    test rcx, rcx
    jz wait_error
    test edx, edx
    jz wait_error
    test r8, r8
    jz wait_error
    
    ; Simple implementation: wait for each fence
    mov ebx, edx    ; fence count
    mov rdi, r8     ; fence array
    xor esi, esi    ; index
    
wait_loop:
    cmp esi, ebx
    jae wait_success
    
    ; Get fence handle
    mov rax, [rdi + rsi*8]
    
    ; Extract slot from handle (lower 8 bits)
    and rax, 0FFh
    
    ; Get Windows event handle
    lea rcx, g_fences
    mov rcx, [rcx + rax*8]
    test rcx, rcx
    jz wait_error
    
    ; Wait for event
    mov edx, INFINITE   ; Timeout (simplified - always infinite)
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne wait_timeout
    
    ; Mark fence as signaled
    lea rcx, g_fenceStates
    mov DWORD PTR [rcx + rax*4], 1
    
    inc esi
    jmp wait_loop
    
wait_success:
    xor eax, eax    ; VK_SUCCESS
    jmp wait_cleanup
    
wait_timeout:
    mov eax, VK_TIMEOUT
    jmp wait_cleanup
    
wait_error:
    mov eax, VK_ERROR_DEVICE_LOST
    
wait_cleanup:
    pop rsi
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkWaitForFencesMASM ENDP

; ============================================================================
; vkResetFencesMASM - Reset fences to unsignaled state
; 
; Parameters:
;   RCX = VkDevice
;   RDX = fenceCount
;   R8  = pointer to VkFence array
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkResetFencesMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    
    ; Validate inputs
    test rcx, rcx
    jz reset_error
    test edx, edx
    jz reset_error
    test r8, r8
    jz reset_error
    
    ; Reset each fence
    mov ebx, edx
    mov rdi, r8
    xor ecx, ecx
    
reset_loop:
    cmp ecx, ebx
    jae reset_success
    
    ; Get fence handle
    mov rax, [rdi + rcx*8]
    
    ; Extract slot
    and rax, 0FFh
    
    ; Get Windows event handle
    push rcx
    lea rcx, g_fences
    mov rcx, [rcx + rax*8]
    call ResetEvent
    pop rcx
    
    ; Mark as unsignaled
    push rcx
    lea rcx, g_fenceStates
    mov DWORD PTR [rcx + rax*4], 0
    pop rcx
    
    inc ecx
    jmp reset_loop
    
reset_success:
    xor eax, eax    ; VK_SUCCESS
    jmp reset_cleanup
    
reset_error:
    mov eax, VK_ERROR_DEVICE_LOST
    
reset_cleanup:
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkResetFencesMASM ENDP

; ============================================================================
; vkGetFenceStatusMASM - Get fence status
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkFence
;
; Returns:
;   RAX = VkResult (VK_SUCCESS if signaled, VK_NOT_READY if not)
; ============================================================================
vkGetFenceStatusMASM PROC
    push rbp
    mov rbp, rsp
    
    ; Validate inputs
    test rcx, rcx
    jz status_error
    test rdx, rdx
    jz status_error
    
    ; Extract slot from fence handle
    mov rax, rdx
    and rax, 0FFh
    
    ; Check fence state
    lea rcx, g_fenceStates
    mov eax, [rcx + rax*4]
    test eax, eax
    jz status_not_ready
    
    xor eax, eax    ; VK_SUCCESS (signaled)
    jmp status_done
    
status_not_ready:
    mov eax, VK_NOT_READY
    jmp status_done
    
status_error:
    mov eax, VK_ERROR_DEVICE_LOST
    
status_done:
    pop rbp
    ret
vkGetFenceStatusMASM ENDP

; ============================================================================
; vkDestroyFenceMASM - Destroy fence
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkFence
;   R8  = allocator (can be NULL)
;
; Returns:
;   void
; ============================================================================
vkDestroyFenceMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Validate inputs
    test rdx, rdx
    jz destroy_done
    
    ; Extract slot
    mov rax, rdx
    and rax, 0FFh
    
    ; Get and close Windows event handle
    lea rcx, g_fences
    mov rcx, [rcx + rax*8]
    test rcx, rcx
    jz destroy_done
    
    call CloseHandle
    
    ; Clear fence entry
    lea rcx, g_fences
    mov QWORD PTR [rcx + rax*8], 0
    
    lea rcx, g_fenceStates
    mov DWORD PTR [rcx + rax*4], 0
    
    ; Decrement count
    dec g_fenceCount
    
destroy_done:
    add rsp, 40h
    pop rbp
    ret
vkDestroyFenceMASM ENDP

END
