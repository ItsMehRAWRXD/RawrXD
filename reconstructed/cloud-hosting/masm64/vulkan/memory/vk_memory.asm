; ============================================================================
; Vulkan Memory Management (MASM x64)
; ============================================================================
; Implements buffer creation, memory allocation, and mapping operations
; Replaces vkCreateBuffer, vkAllocateMemory, vkBindBufferMemory, vkMapMemory
; ============================================================================

.code

INCLUDE vulkan_types.inc

; ============================================================================
; External references
; ============================================================================
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN GetProcessHeap:PROC
EXTERN RtlZeroMemory:PROC
EXTERN RtlCopyMemory:PROC

; ============================================================================
; Buffer tracking
; ============================================================================
.data
    g_bufferPool        VkInternalBuffer 64 DUP(<>)  ; Max 64 buffers
    g_bufferCount       DWORD 0
    g_nextBufferHandle  QWORD 1000h

; ============================================================================
; vkCreateBufferMASM - Create buffer object
; 
; Parameters:
;   RCX = VkDevice
;   RDX = pointer to VkBufferCreateInfo
;   R8  = allocator (can be NULL)
;   R9  = pointer to VkBuffer handle
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkCreateBufferMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    
    ; Validate inputs
    test rcx, rcx
    jz buffer_error
    test rdx, rdx
    jz buffer_error
    test r9, r9
    jz buffer_error
    
    ; Check if we have space for more buffers
    mov eax, g_bufferCount
    cmp eax, 64
    jae buffer_error_full
    
    ; Get buffer size from create info
    mov rbx, [rdx + VkBufferCreateInfo.size]
    test rbx, rbx
    jz buffer_error
    
    ; Find free slot in buffer pool
    xor ecx, ecx
    lea rdi, g_bufferPool
    
find_slot_loop:
    cmp ecx, 64
    jae buffer_error_full
    
    ; Check if slot is free (buffer handle is 0)
    mov rax, [rdi + VkInternalBuffer.buffer]
    test rax, rax
    jz found_slot
    
    ; Move to next slot
    inc ecx
    add rdi, SIZEOF VkInternalBuffer
    jmp find_slot_loop
    
found_slot:
    ; Create buffer handle
    mov rax, g_nextBufferHandle
    inc g_nextBufferHandle
    mov [rdi + VkInternalBuffer.buffer], rax
    
    ; Store buffer properties
    mov [rdi + VkInternalBuffer.size], rbx
    mov eax, [rdx + VkBufferCreateInfo.usage]
    mov [rdi + VkInternalBuffer.flags], eax
    mov QWORD PTR [rdi + VkInternalBuffer.memory], 0
    mov QWORD PTR [rdi + VkInternalBuffer.mapped], 0
    
    ; Return buffer handle
    mov rax, [rdi + VkInternalBuffer.buffer]
    mov [r9], rax
    
    ; Increment buffer count
    inc g_bufferCount
    
    xor eax, eax    ; VK_SUCCESS
    jmp buffer_cleanup
    
buffer_error_full:
    mov eax, VK_ERROR_OUT_OF_HOST_MEMORY
    jmp buffer_cleanup
    
buffer_error:
    mov eax, VK_ERROR_INITIALIZATION_FAILED
    
buffer_cleanup:
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkCreateBufferMASM ENDP

; ============================================================================
; vkAllocateMemoryMASM - Allocate device memory
; 
; Parameters:
;   RCX = VkDevice
;   RDX = pointer to VkMemoryAllocateInfo
;   R8  = allocator (can be NULL)
;   R9  = pointer to VkDeviceMemory handle
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkAllocateMemoryMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    
    ; Validate inputs
    test rcx, rcx
    jz alloc_error
    test rdx, rdx
    jz alloc_error
    test r9, r9
    jz alloc_error
    
    ; Get allocation size
    mov rbx, [rdx + VkMemoryAllocateInfo.allocationSize]
    test rbx, rbx
    jz alloc_error
    
    ; Allocate memory from process heap
    call GetProcessHeap
    test rax, rax
    jz alloc_error
    
    mov rcx, rax    ; Heap handle
    xor edx, edx    ; Flags
    mov r8, rbx     ; Size
    call HeapAlloc
    test rax, rax
    jz alloc_error_oom
    
    ; Return memory handle (use pointer as handle)
    mov [r9], rax
    
    xor eax, eax    ; VK_SUCCESS
    jmp alloc_cleanup
    
alloc_error_oom:
    mov eax, VK_ERROR_OUT_OF_HOST_MEMORY
    jmp alloc_cleanup
    
alloc_error:
    mov eax, VK_ERROR_INITIALIZATION_FAILED
    
alloc_cleanup:
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkAllocateMemoryMASM ENDP

; ============================================================================
; vkBindBufferMemoryMASM - Bind memory to buffer
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkBuffer
;   R8  = VkDeviceMemory
;   R9  = offset (VkDeviceSize)
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkBindBufferMemoryMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rdi
    
    ; Validate inputs
    test rcx, rcx
    jz bind_error
    test rdx, rdx
    jz bind_error
    test r8, r8
    jz bind_error
    
    ; Find buffer in pool
    xor ecx, ecx
    lea rdi, g_bufferPool
    
bind_find_loop:
    cmp ecx, 64
    jae bind_error
    
    mov rax, [rdi + VkInternalBuffer.buffer]
    cmp rax, rdx
    je bind_found
    
    inc ecx
    add rdi, SIZEOF VkInternalBuffer
    jmp bind_find_loop
    
bind_found:
    ; Bind memory to buffer
    mov [rdi + VkInternalBuffer.memory], r8
    
    xor eax, eax    ; VK_SUCCESS
    jmp bind_cleanup
    
bind_error:
    mov eax, VK_ERROR_INITIALIZATION_FAILED
    
bind_cleanup:
    pop rdi
    add rsp, 40h
    pop rbp
    ret
vkBindBufferMemoryMASM ENDP

; ============================================================================
; vkMapMemoryMASM - Map device memory to host pointer
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkDeviceMemory
;   R8  = offset (VkDeviceSize)
;   R9  = size (VkDeviceSize)
;   [rbp+48] = flags
;   [rbp+56] = pointer to void* (output)
;
; Returns:
;   RAX = VkResult
; ============================================================================
vkMapMemoryMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Validate inputs
    test rcx, rcx
    jz map_error
    test rdx, rdx
    jz map_error
    
    mov rax, [rbp+56]
    test rax, rax
    jz map_error
    
    ; Memory handle is the pointer itself, add offset
    mov rcx, rdx
    add rcx, r8
    
    ; Return mapped pointer
    mov rax, [rbp+56]
    mov [rax], rcx
    
    xor eax, eax    ; VK_SUCCESS
    jmp map_cleanup
    
map_error:
    mov eax, VK_ERROR_MEMORY_MAP_FAILED
    
map_cleanup:
    add rsp, 40h
    pop rbp
    ret
vkMapMemoryMASM ENDP

; ============================================================================
; vkUnmapMemoryMASM - Unmap device memory
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkDeviceMemory
;
; Returns:
;   void
; ============================================================================
vkUnmapMemoryMASM PROC
    ; No-op in this implementation (always mapped)
    ret
vkUnmapMemoryMASM ENDP

; ============================================================================
; vkFreeMemoryMASM - Free device memory
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkDeviceMemory
;   R8  = allocator (can be NULL)
;
; Returns:
;   void
; ============================================================================
vkFreeMemoryMASM PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    
    ; Validate inputs
    test rdx, rdx
    jz free_done
    
    ; Free memory from heap
    call GetProcessHeap
    test rax, rax
    jz free_done
    
    mov rcx, rax    ; Heap handle
    xor edx, edx    ; Flags
    mov r8, rdx     ; Memory pointer (from RDX before)
    call HeapFree
    
free_done:
    pop rbx
    add rsp, 40h
    pop rbp
    ret
vkFreeMemoryMASM ENDP

; ============================================================================
; vkDestroyBufferMASM - Destroy buffer
; 
; Parameters:
;   RCX = VkDevice
;   RDX = VkBuffer
;   R8  = allocator (can be NULL)
;
; Returns:
;   void
; ============================================================================
vkDestroyBufferMASM PROC
    push rbp
    mov rbp, rsp
    push rdi
    
    ; Find and clear buffer from pool
    xor ecx, ecx
    lea rdi, g_bufferPool
    
destroy_find_loop:
    cmp ecx, 64
    jae destroy_done
    
    mov rax, [rdi + VkInternalBuffer.buffer]
    cmp rax, rdx
    je destroy_found
    
    inc ecx
    add rdi, SIZEOF VkInternalBuffer
    jmp destroy_find_loop
    
destroy_found:
    ; Clear buffer entry
    mov QWORD PTR [rdi + VkInternalBuffer.buffer], 0
    mov QWORD PTR [rdi + VkInternalBuffer.memory], 0
    mov QWORD PTR [rdi + VkInternalBuffer.size], 0
    mov DWORD PTR [rdi + VkInternalBuffer.flags], 0
    mov QWORD PTR [rdi + VkInternalBuffer.mapped], 0
    
    ; Decrement buffer count
    dec g_bufferCount
    
destroy_done:
    pop rdi
    pop rbp
    ret
vkDestroyBufferMASM ENDP

END
