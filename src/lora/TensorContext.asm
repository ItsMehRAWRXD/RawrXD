; ============================================================================
; TensorContext.asm - Zero-Overhead Tensor Abstraction for AVX GEMM
; ============================================================================
; Pure x64 MASM implementation with no dependencies.
; Provides:
;   - Tensor struct (64 bytes, cache-line aligned)
;   - Arena allocator for gigabyte-scale weights
;   - Memory management for transformer layers
;
; Design Goals:
;   - Zero heap fragmentation (arena allocation)
;   - 32-byte alignment guarantee for AVX operations
;   - L2 cache blocking preservation
;   - Minimal overhead (struct is just metadata)
; ============================================================================

; ============================================================================
; Constants
; ============================================================================
TENSOR_MAX_DIMS      equ 4
TENSOR_ALIGNMENT     equ 32      ; AVX alignment
ARENA_DEFAULT_SIZE   equ 1073741824  ; 1GB default arena
CACHE_LINE_SIZE      equ 64

; ============================================================================
; Tensor Flags
; ============================================================================
TENSOR_FLAG_NONE     equ 00000000h
TENSOR_FLAG_OWNED    equ 00000001h   ; Arena owns the memory
TENSOR_FLAG_ALIGNED  equ 00000002h   ; 32-byte aligned
TENSOR_FLAG_CONTIGUOUS equ 00000004h ; Contiguous memory

; ============================================================================
; Data Types
; ============================================================================
DTYPE_FLOAT32        equ 0
DTYPE_FLOAT16        equ 1
DTYPE_INT8            equ 2

; ============================================================================
; Tensor STRUCT (64 bytes - 1 cache line)
; ============================================================================
; Zero-overhead wrapper for aligned memory buffers
; Tracks dimensionality, strides, and data pointers
; ============================================================================
Tensor STRUCT
    dims        dq TENSOR_MAX_DIMS dup(?)  ; 32 bytes: Dimensions [d0, d1, d2, d3]
    strides     dq TENSOR_MAX_DIMS dup(?)  ; 32 bytes: Strides in elements
    data        dq ?                        ; 8 bytes: Pointer to float data
    elem_count  dq ?                        ; 8 bytes: Total element count (renamed from 'size')
    flags       dd ?                        ; 4 bytes: Ownership/alignment flags
    dtype       dd ?                        ; 4 bytes: Data type enum
    _padding    dq 2 dup(?)                 ; 16 bytes: Pad to 64 bytes
Tensor ENDS

; ============================================================================
; Arena Allocator STRUCT
; ============================================================================
; Manages large contiguous memory blocks for weights
; Bump pointer allocation - O(1), zero fragmentation
; ============================================================================
Arena STRUCT
    base        dq ?        ; Base pointer of allocated memory
    current     dq ?        ; Current allocation pointer
    capacity    dq ?        ; Total capacity in bytes
    allocated    dq ?        ; Bytes currently allocated
    _reserved   dq 4 dup(?) ; Reserved for future use
Arena ENDS

.code

; ============================================================================
; Arena_Init
; Initialize arena allocator with specified capacity
; 
; Parameters:
;   RCX = Arena* arena
;   RDX = size_t capacity (bytes, will be rounded to 32-byte boundary)
; 
; Returns:
;   RAX = 0 on success, non-zero on failure
; ============================================================================
Arena_Init PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov rbx, rcx               ; RBX = arena
    mov rsi, rdx               ; RSI = capacity
    
    ; Round capacity to 32-byte boundary
    add rsi, 31
    and rsi, -32
    
    ; Allocate memory using VirtualAlloc for large blocks
    ; This avoids heap fragmentation entirely
    ; VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    xor rcx, rcx               ; lpAddress = NULL
    mov rdx, rsi               ; dwSize
    mov r8, 3000h              ; MEM_COMMIT | MEM_RESERVE
    mov r9, 4                  ; PAGE_READWRITE
    
    ; Call VirtualAlloc (kernel32.lib)
    extern __imp_VirtualAlloc:PROC
    call __imp_VirtualAlloc
    
    test rax, rax
    jz InitFailed
    
    ; Store base pointer
    mov [rbx + Arena.base], rax
    mov [rbx + Arena.current], rax
    mov [rbx + Arena.capacity], rsi
    mov qword ptr [rbx + Arena.allocated], 0
    
    xor rax, rax                ; Success
    jmp Done
    
InitFailed:
    mov rax, 1                 ; Failure
    
Done:
    pop rsi
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
Arena_Init ENDP

; ============================================================================
; Arena_Alloc
; Allocate aligned memory from arena (bump pointer)
; 
; Parameters:
;   RCX = Arena* arena
;   RDX = size_t bytes (will be rounded to 32-byte boundary)
; 
; Returns:
;   RAX = pointer to allocated memory (32-byte aligned), or NULL on failure
; ============================================================================
Arena_Alloc PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov rbx, rcx               ; RBX = arena
    
    ; Round up to 32-byte alignment
    add rdx, 31
    and rdx, -32
    
    ; Check capacity
    mov rax, [rbx + Arena.allocated]
    add rax, rdx
    cmp rax, [rbx + Arena.capacity]
    ja AllocFailed
    
    ; Bump pointer allocation
    mov rax, [rbx + Arena.current]
    add [rbx + Arena.current], rdx
    add [rbx + Arena.allocated], rdx
    
    jmp Done
    
AllocFailed:
    xor rax, rax               ; NULL
    
Done:
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
Arena_Alloc ENDP

; ============================================================================
; Arena_Reset
; Reset arena for reuse (keeps memory, resets pointer)
; 
; Parameters:
;   RCX = Arena* arena
; ============================================================================
Arena_Reset PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    mov rax, [rcx + Arena.base]
    mov [rcx + Arena.current], rax
    mov qword ptr [rcx + Arena.allocated], 0
    
    pop rbp
    ret
Arena_Reset ENDP

; ============================================================================
; Arena_Free
; Free arena memory
; 
; Parameters:
;   RCX = Arena* arena
; ============================================================================
Arena_Free PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov rbx, rcx               ; RBX = arena
    
    mov rax, [rbx + Arena.base]
    test rax, rax
    jz Done
    
    ; VirtualFree the base
    ; VirtualFree(lpAddress, 0, MEM_RELEASE)
    mov rcx, rax               ; lpAddress
    xor rdx, rdx               ; dwSize = 0
    mov r8, 8000h              ; MEM_RELEASE
    
    extern __imp_VirtualFree:PROC
    call __imp_VirtualFree
    
    ; Clear arena struct
    mov qword ptr [rbx + Arena.base], 0
    mov qword ptr [rbx + Arena.current], 0
    mov qword ptr [rbx + Arena.capacity], 0
    mov qword ptr [rbx + Arena.allocated], 0
    
Done:
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
Arena_Free ENDP

; ============================================================================
; Tensor_Init
; Initialize a tensor from existing memory (no ownership)
; 
; Parameters:
;   RCX = Tensor* tensor
;   RDX = float* data
;   R8  = size_t dim0
;   R9  = size_t dim1
;   [RSP+40] = size_t dim2 (optional, 0 for 2D)
;   [RSP+48] = size_t dim3 (optional, 0 for 3D)
; ============================================================================
Tensor_Init PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    ; Store data pointer
    mov [rcx + Tensor.data], rdx
    
    ; Store dimensions
    mov [rcx + Tensor.dims + 0], r8      ; dim0
    mov [rcx + Tensor.dims + 8], r9      ; dim1
    
    ; Load optional dimensions from stack
    mov rax, [rsp + 40 + 8]              ; +8 for rbp push
    mov [rcx + Tensor.dims + 16], rax    ; dim2
    mov rax, [rsp + 48 + 8]
    mov [rcx + Tensor.dims + 24], rax    ; dim3
    
    ; Calculate strides (row-major)
    ; stride[3] = 1
    ; stride[2] = dim3
    ; stride[1] = dim2 * dim3
    ; stride[0] = dim1 * dim2 * dim3
    
    mov rax, [rcx + Tensor.dims + 24]    ; dim3
    test rax, rax
    jnz Calc3D
    
    ; 2D tensor: strides = [dim1, 1]
    mov qword ptr [rcx + Tensor.strides + 0], r9  ; stride0 = dim1
    mov qword ptr [rcx + Tensor.strides + 8], 1   ; stride1 = 1
    mov qword ptr [rcx + Tensor.strides + 16], 0
    mov qword ptr [rcx + Tensor.strides + 24], 0
    
    ; Calculate size = dim0 * dim1
    mov rax, r8
    imul rax, r9
    mov [rcx + Tensor.elem_count], rax
    jmp SetFlags
    
Calc3D:
    ; 3D/4D tensor stride calculation
    mov rax, [rcx + Tensor.dims + 24]    ; dim3
    mov [rcx + Tensor.strides + 24], rax ; stride3 = 1 (will multiply)
    
    mov rbx, [rcx + Tensor.dims + 16]    ; dim2
    imul rbx, rax                         ; stride2 = dim2 * dim3
    mov [rcx + Tensor.strides + 16], rbx
    
    mov rax, [rcx + Tensor.dims + 8]     ; dim1
    imul rax, rbx                         ; stride1 = dim1 * dim2 * dim3
    mov [rcx + Tensor.strides + 8], rax
    
    mov rbx, [rcx + Tensor.dims + 0]     ; dim0
    imul rbx, rax                         ; stride0 = dim0 * ...
    mov [rcx + Tensor.strides + 0], rbx
    
    ; Calculate total size
    mov rax, [rcx + Tensor.dims + 0]
    imul rax, [rcx + Tensor.dims + 8]
    imul rax, [rcx + Tensor.dims + 16]
    imul rax, [rcx + Tensor.dims + 24]
    mov [rcx + Tensor.elem_count], rax
    
SetFlags:
    ; Set flags: not owned, check alignment
    mov dword ptr [rcx + Tensor.flags], TENSOR_FLAG_CONTIGUOUS
    
    ; Check if data is 32-byte aligned
    test rdx, 31
    jnz NotAligned
    or dword ptr [rcx + Tensor.flags], TENSOR_FLAG_ALIGNED
    
NotAligned:
    mov dword ptr [rcx + Tensor.dtype], DTYPE_FLOAT32
    
    mov rsp, rbp
    pop rbp
    ret
Tensor_Init ENDP

; ============================================================================
; Tensor_Alloc
; Allocate a new tensor from arena (takes ownership)
; 
; Parameters:
;   RCX = Tensor* tensor
;   RDX = Arena* arena
;   R8  = size_t dim0
;   R9  = size_t dim1
;   [RSP+40] = size_t dim2 (optional)
;   [RSP+48] = size_t dim3 (optional)
; 
; Returns:
;   RAX = 0 on success, non-zero on failure
; ============================================================================
Tensor_Alloc PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov rbx, rcx               ; RBX = tensor
    mov rsi, rdx               ; RSI = arena
    
    ; Calculate total elements
    mov rax, r8                ; dim0
    imul rax, r9               ; * dim1
    
    mov rcx, [rsp + 40 + 24]   ; dim2 (accounting for pushes)
    test rcx, rcx
    jz CalcSize2D
    imul rax, rcx              ; * dim2
    
    mov rcx, [rsp + 48 + 24]   ; dim3
    test rcx, rcx
    jz CalcSize3D
    imul rax, rcx              ; * dim3
    
CalcSize3D:
    jmp AllocMemory
    
CalcSize2D:
    ; Already have dim0 * dim1 in rax
    
AllocMemory:
    ; Calculate bytes = elements * sizeof(float)
    shl rax, 2                 ; * 4 bytes per float
    
    ; Allocate from arena
    mov rcx, rsi               ; Arena
    mov rdx, rax               ; Size in bytes
    call Arena_Alloc
    
    test rax, rax
    jz AllocFailed
    
    ; Initialize tensor with allocated memory
    mov rcx, rbx               ; Tensor
    mov rdx, rax               ; Data pointer
    ; dim0, dim1 already in r8, r9
    ; dim2, dim3 on stack
    call Tensor_Init
    
    ; Mark as owned
    or dword ptr [rbx + Tensor.flags], TENSOR_FLAG_OWNED
    
    xor rax, rax               ; Success
    jmp Done
    
AllocFailed:
    mov rax, 1                 ; Failure
    
Done:
    pop rsi
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
Tensor_Alloc ENDP

; ============================================================================
; Tensor_GetElement
; Get pointer to element at indices
; 
; Parameters:
;   RCX = Tensor* tensor
;   RDX = size_t i0
;   R8  = size_t i1
;   R9  = size_t i2 (optional)
;   [RSP+40] = size_t i3 (optional)
; 
; Returns:
;   RAX = float* pointer to element
; ============================================================================
Tensor_GetElement PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    
    ; Calculate offset = i0 * stride[0] + i1 * stride[1] + ...
    mov rax, [rcx + Tensor.strides + 0]
    imul rax, rdx               ; i0 * stride0
    
    mov rdx, [rcx + Tensor.strides + 8]
    imul rdx, r8                ; i1 * stride1
    add rax, rdx
    
    ; Check for 3D/4D
    mov rdx, [rcx + Tensor.dims + 16]
    test rdx, rdx
    jz Done2D
    
    mov rdx, [rsp + 40 + 8]    ; i2 (accounting for rbp)
    mov r8, [rcx + Tensor.strides + 16]
    imul rdx, r8
    add rax, rdx
    
    mov rdx, [rcx + Tensor.dims + 24]
    test rdx, rdx
    jz Done3D
    
    mov rdx, [rsp + 48 + 8]    ; i3
    mov r8, [rcx + Tensor.strides + 24]
    imul rdx, r8
    add rax, rdx
    
Done3D:
Done2D:
    ; Convert to byte offset and add to base
    shl rax, 2                  ; * sizeof(float)
    add rax, [rcx + Tensor.data]
    
    pop rbp
    ret
Tensor_GetElement ENDP

; ============================================================================
; Tensor_Zero
; Zero out tensor data
; 
; Parameters:
;   RCX = Tensor* tensor
; ============================================================================
Tensor_Zero PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog
    
    mov rax, [rcx + Tensor.data]
    mov rdx, [rcx + Tensor.elem_count]
    shl rdx, 2                  ; Convert to bytes
    
    ; Use AVX to zero 32 bytes at a time
    vxorps ymm0, ymm0, ymm0
    
    shr rdx, 5                  ; / 32
    jz ZeroRemainder
    
ZeroLoop:
    vmovaps [rax], ymm0
    add rax, 32
    dec rdx
    jnz ZeroLoop
    
ZeroRemainder:
    vzeroupper
    
    mov rsp, rbp
    pop rbp
    ret
Tensor_Zero ENDP

END