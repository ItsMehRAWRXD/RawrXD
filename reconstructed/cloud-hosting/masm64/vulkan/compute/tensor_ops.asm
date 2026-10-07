; ============================================================================
; Tensor Operations (MASM x64)
; ============================================================================
; Implements tensor memory management and basic operations
; ============================================================================

.code

INCLUDE vulkan_types.inc

; ============================================================================
; External functions
; ============================================================================
EXTERN RtlCopyMemory:PROC
EXTERN RtlZeroMemory:PROC

; ============================================================================
; Tensor pool
; ============================================================================
.data
    g_tensorPool        TensorDescriptor 64 DUP(<>)
    g_tensorCount       DWORD 0

; ============================================================================
; TensorCreate - Create and initialize a tensor
; 
; Parameters:
;   RCX = pointer to dimensions array (int32_t[8])
;   RDX = number of dimensions
;   R8  = data type (0=FP32, 1=FP16, 2=INT8)
;   R9  = pointer to output TensorDescriptor*
;
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
TensorCreate PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    push rsi
    
    ; Validate inputs
    test rcx, rcx
    jz tensor_error
    test edx, edx
    jz tensor_error
    cmp edx, 8
    ja tensor_error
    test r9, r9
    jz tensor_error
    
    ; Find free slot
    xor eax, eax
    lea rdi, g_tensorPool
    
tensor_find_slot:
    cmp eax, 64
    jae tensor_error_full
    
    ; Check if slot is free (data pointer is NULL)
    mov rbx, [rdi + TensorDescriptor.data]
    test rbx, rbx
    jz tensor_found_slot
    
    inc eax
    add rdi, SIZEOF TensorDescriptor
    jmp tensor_find_slot
    
tensor_found_slot:
    ; Copy dimensions
    mov rsi, rcx
    lea rdi, [rdi + TensorDescriptor.dimensions]
    mov ecx, edx
    rep movsd
    
    ; Restore rdi to point to tensor descriptor
    sub rdi, edx
    sub rdi, edx
    sub rdi, edx
    sub rdi, edx
    
    ; Store number of dimensions
    lea rdi, g_tensorPool
    imul eax, SIZEOF TensorDescriptor
    add rdi, rax
    mov [rdi + TensorDescriptor.numDims], edx
    
    ; Store data type
    mov [rdi + TensorDescriptor.dataType], r8d
    
    ; Calculate total size
    mov eax, 1
    mov ecx, edx
    lea rsi, [rdi + TensorDescriptor.dimensions]
    
tensor_calc_size:
    test ecx, ecx
    jz tensor_size_done
    
    imul eax, [rsi]
    add rsi, 4
    dec ecx
    jmp tensor_calc_size
    
tensor_size_done:
    ; Multiply by element size
    cmp r8d, 0  ; FP32
    je tensor_size_fp32
    cmp r8d, 1  ; FP16
    je tensor_size_fp16
    ; INT8
    jmp tensor_size_int8
    
tensor_size_fp32:
    shl rax, 2  ; * 4 bytes
    jmp tensor_size_store
    
tensor_size_fp16:
    shl rax, 1  ; * 2 bytes
    jmp tensor_size_store
    
tensor_size_int8:
    ; * 1 byte (no change)
    
tensor_size_store:
    mov [rdi + TensorDescriptor.totalSize], rax
    
    ; Data pointer starts as NULL (must be allocated separately)
    mov QWORD PTR [rdi + TensorDescriptor.data], 0
    
    ; Return pointer to tensor descriptor
    mov [r9], rdi
    
    ; Increment count
    inc g_tensorCount
    
    xor eax, eax    ; Success
    jmp tensor_cleanup
    
tensor_error_full:
    mov eax, -1
    jmp tensor_cleanup
    
tensor_error:
    mov eax, -1
    
tensor_cleanup:
    pop rsi
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
TensorCreate ENDP

; ============================================================================
; TensorAllocate - Allocate memory for tensor data
; 
; Parameters:
;   RCX = pointer to TensorDescriptor
;   RDX = VkDevice (for memory allocation)
;
; Returns:
;   RAX = pointer to allocated data, or NULL on error
; ============================================================================
TensorAllocate PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    
    ; Validate input
    test rcx, rcx
    jz alloc_error
    
    mov rbx, rcx
    
    ; Get size
    mov r8, [rbx + TensorDescriptor.totalSize]
    test r8, r8
    jz alloc_error
    
    ; Allocate memory (call vkAllocateMemoryMASM)
    ; For now, use Windows heap
    EXTERN GetProcessHeap:PROC
    EXTERN HeapAlloc:PROC
    
    call GetProcessHeap
    test rax, rax
    jz alloc_error
    
    mov rcx, rax
    xor edx, edx    ; Flags
    mov r8, [rbx + TensorDescriptor.totalSize]
    call HeapAlloc
    test rax, rax
    jz alloc_error
    
    ; Store pointer in tensor
    mov [rbx + TensorDescriptor.data], rax
    
    jmp alloc_done
    
alloc_error:
    xor eax, eax
    
alloc_done:
    pop rbx
    add rsp, 40h
    pop rbp
    ret
TensorAllocate ENDP

; ============================================================================
; TensorCopy - Copy tensor data
; 
; Parameters:
;   RCX = pointer to destination TensorDescriptor
;   RDX = pointer to source TensorDescriptor
;
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
TensorCopy PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    push rdi
    push rsi
    
    ; Validate inputs
    test rcx, rcx
    jz copy_error
    test rdx, rdx
    jz copy_error
    
    mov rdi, rcx    ; Destination
    mov rsi, rdx    ; Source
    
    ; Check sizes match
    mov rax, [rdi + TensorDescriptor.totalSize]
    mov rbx, [rsi + TensorDescriptor.totalSize]
    cmp rax, rbx
    jne copy_error
    
    ; Check data pointers
    mov rcx, [rdi + TensorDescriptor.data]
    test rcx, rcx
    jz copy_error
    
    mov rdx, [rsi + TensorDescriptor.data]
    test rdx, rdx
    jz copy_error
    
    ; Copy memory
    mov r8, rax     ; Size
    call RtlCopyMemory
    
    xor eax, eax    ; Success
    jmp copy_done
    
copy_error:
    mov eax, -1
    
copy_done:
    pop rsi
    pop rdi
    pop rbx
    add rsp, 40h
    pop rbp
    ret
TensorCopy ENDP

; ============================================================================
; TensorZero - Zero out tensor data
; 
; Parameters:
;   RCX = pointer to TensorDescriptor
;
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
TensorZero PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    
    ; Validate input
    test rcx, rcx
    jz zero_error
    
    mov rbx, rcx
    
    ; Get data pointer and size
    mov rcx, [rbx + TensorDescriptor.data]
    test rcx, rcx
    jz zero_error
    
    mov rdx, [rbx + TensorDescriptor.totalSize]
    call RtlZeroMemory
    
    xor eax, eax    ; Success
    jmp zero_done
    
zero_error:
    mov eax, -1
    
zero_done:
    pop rbx
    add rsp, 40h
    pop rbp
    ret
TensorZero ENDP

; ============================================================================
; TensorFree - Free tensor resources
; 
; Parameters:
;   RCX = pointer to TensorDescriptor
;
; Returns:
;   void
; ============================================================================
TensorFree PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rbx
    
    ; Validate input
    test rcx, rcx
    jz free_done
    
    mov rbx, rcx
    
    ; Free data if allocated
    mov rax, [rbx + TensorDescriptor.data]
    test rax, rax
    jz free_clear
    
    ; Free memory using Windows heap
    EXTERN GetProcessHeap:PROC
    EXTERN HeapFree:PROC
    
    push rax
    call GetProcessHeap
    mov rcx, rax
    xor edx, edx
    pop r8
    call HeapFree
    
free_clear:
    ; Clear tensor descriptor
    mov rcx, rbx
    mov rdx, SIZEOF TensorDescriptor
    call RtlZeroMemory
    
    ; Decrement count
    dec g_tensorCount
    
free_done:
    pop rbx
    add rsp, 40h
    pop rbp
    ret
TensorFree ENDP

; ============================================================================
; TensorGetShape - Get tensor shape information
; 
; Parameters:
;   RCX = pointer to TensorDescriptor
;   RDX = pointer to output dimensions array (int32_t[8])
;   R8  = pointer to output numDims
;
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
TensorGetShape PROC
    push rbp
    mov rbp, rsp
    push rdi
    push rsi
    
    ; Validate inputs
    test rcx, rcx
    jz shape_error
    test rdx, rdx
    jz shape_error
    test r8, r8
    jz shape_error
    
    ; Copy dimensions
    lea rsi, [rcx + TensorDescriptor.dimensions]
    mov rdi, rdx
    mov ecx, 8
    rep movsd
    
    ; Copy numDims
    mov eax, [rsi + TensorDescriptor.numDims - TensorDescriptor.dimensions - 32]
    mov [r8], eax
    
    xor eax, eax    ; Success
    jmp shape_done
    
shape_error:
    mov eax, -1
    
shape_done:
    pop rsi
    pop rdi
    pop rbp
    ret
TensorGetShape ENDP

END
