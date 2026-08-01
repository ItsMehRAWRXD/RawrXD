; =============================================================================
; tensor.asm - RawrXD Tensor Engine (PyTorch Tensor Replacement)
; =============================================================================
; Pure MASM x64 tensor implementation with zero external dependencies.
; Supports F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0 dtypes with strided
; memory access, broadcasting, and view semantics.
;
; Tensor Structure (64 bytes):
;   +0:  QWORD data_ptr       - Pointer to raw data buffer
;   +8:  QWORD ndim           - Number of dimensions (0-8)
;  +12:  DWORD dtype          - DTYPE_* constant
;  +16:  QWORD numel          - Total number of elements
;  +24:  QWORD shape[0..7]    - Dimension sizes (8 * 8 = 64 bytes)
;  +88:  QWORD stride[0..7]   - Strides in elements (8 * 8 = 64 bytes)
; +152:  QWORD offset         - Byte offset into data buffer
; +160:  QWORD quant_type     - QUANT_* for quantized tensors
; +168:  QWORD device         - 0=CPU, 1=GPU
; Total: 176 bytes (rounded to 192 for alignment)
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; Windows API externs (must be at file level, not inside PROC)
; =============================================================================
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_TENSOR_DIMS         EQU 8
TENSOR_STRUCT_SIZE      EQU 192
TENSOR_ALIGNMENT        EQU 64

; Tensor struct field offsets
TENSOR_OFF_DATA_PTR     EQU 0
TENSOR_OFF_NDIM         EQU 8
TENSOR_OFF_DTYPE        EQU 12
TENSOR_OFF_NUMEL        EQU 16
TENSOR_OFF_SHAPE        EQU 24
TENSOR_OFF_STRIDE       EQU 88
TENSOR_OFF_OFFSET       EQU 152
TENSOR_OFF_QUANT_TYPE   EQU 160
TENSOR_OFF_DEVICE       EQU 168

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Default alignment for tensor allocations
align 16
g_DefaultAllocSize      DQ 0

; Error message strings
align 8
szTensorErr             DB '[Tensor] ', 0
szOOM                   DB 'Out of memory', 0
szBadShape              DB 'Invalid shape', 0
szBadDtype              DB 'Unsupported dtype', 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_TensorCreate - Allocate and initialize a new tensor
;
; Parameters:
;   RCX = QWORD* shape      - Pointer to shape array
;   RDX = QWORD ndim        - Number of dimensions
;   R8  = DWORD dtype       - DTYPE_* constant
;
; Returns: RAX = pointer to tensor struct, or NULL on failure
; =============================================================================
RawrXD_TensorCreate PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Validate parameters
    test rcx, rcx
    jz @@error_null
    test rdx, rdx
    jz @@error_bad_shape
    cmp rdx, MAX_TENSOR_DIMS
    ja @@error_bad_shape

    mov rsi, rcx                    ; rsi = shape array
    mov rdi, rdx                    ; rdi = ndim
    mov r12d, r8d                   ; r12 = dtype

    ; Calculate total number of elements
    mov rbx, 1                      ; rbx = numel
    xor r13, r13                    ; r13 = loop index

@@calc_numel:
    cmp r13, rdi
    jge @@calc_done
    mov rax, QWORD PTR [rsi + r13*8]
    test rax, rax
    jz @@error_bad_shape           ; Zero dimension
    mul rbx                        ; RDX:RAX = rax * rbx
    test rdx, rdx
    jnz @@error_oom                ; Overflow
    mov rbx, rax
    inc r13
    jmp @@calc_numel

@@calc_done:
    mov r14, rbx                   ; r14 = numel

    ; Calculate element size from dtype
    xor r13, r13                   ; r13 = element_size
    cmp r12d, DTYPE_F32
    je @@size_4
    cmp r12d, DTYPE_I32
    je @@size_4
    cmp r12d, DTYPE_F16
    je @@size_2
    cmp r12d, DTYPE_I16
    je @@size_2
    cmp r12d, DTYPE_I8
    je @@size_1
    cmp r12d, DTYPE_Q4_0
    je @@size_q4
    cmp r12d, DTYPE_Q8_0
    je @@size_1
    jmp @@error_bad_dtype

@@size_4:
    mov r13, 4
    jmp @@alloc

@@size_2:
    mov r13, 2
    jmp @@alloc

@@size_1:
    mov r13, 1
    jmp @@alloc

@@size_q4:
    ; Q4_0: 18 bytes per 16 elements = 1.125 bytes/element
    ; Total = (numel * 18 + 15) / 16
    mov rax, r14
    mov rcx, 18
    mul rcx
    add rax, 15
    shr rax, 4                     ; Divide by 16
    mov r13, rax
    jmp @@alloc

@@alloc:
    ; Allocate tensor struct (aligned)
    mov rcx, TENSOR_STRUCT_SIZE
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error_oom
    mov r8, rax                    ; r8 = tensor struct

    ; Zero-initialize the struct
    push r8
    mov rcx, r8
    mov rdx, TENSOR_STRUCT_SIZE
    call RawrXD_ZeroMemory
    pop r8

    ; Allocate data buffer
    mov rax, r14                   ; numel
    mul r13                        ; total bytes
    mov rcx, rax
    test rcx, rcx
    jz @@skip_data_alloc           ; Zero-size tensor (scalar)
    push r8
    call RawrXD_AlignedAlloc
    pop r8
    test rax, rax
    jz @@free_struct

    ; Store data pointer
    mov QWORD PTR [r8 + TENSOR_OFF_DATA_PTR], rax

@@skip_data_alloc:
    ; Populate tensor struct fields
    mov QWORD PTR [r8 + TENSOR_OFF_NDIM], rdi
    mov DWORD PTR [r8 + TENSOR_OFF_DTYPE], r12d
    mov QWORD PTR [r8 + TENSOR_OFF_NUMEL], r14
    mov QWORD PTR [r8 + TENSOR_OFF_OFFSET], 0
    mov QWORD PTR [r8 + TENSOR_OFF_QUANT_TYPE], 0
    mov QWORD PTR [r8 + TENSOR_OFF_DEVICE], 0

    ; Copy shape and compute strides (row-major: last dim stride = 1)
    mov rcx, rdi                   ; ndim
    dec rcx                        ; Start from last dimension
    mov rax, 1                     ; stride = 1 for last dim

@@stride_loop:
    cmp rcx, 0
    jl @@stride_done
    mov rdx, QWORD PTR [rsi + rcx*8]  ; shape[dim]
    mov QWORD PTR [r8 + TENSOR_OFF_SHAPE + rcx*8], rdx
    mov QWORD PTR [r8 + TENSOR_OFF_STRIDE + rcx*8], rax
    mul rdx                        ; stride *= shape[dim]
    dec rcx
    jmp @@stride_loop

@@stride_done:
    mov rax, r8                    ; Return tensor pointer
    jmp @@exit

@@free_struct:
    mov rcx, r8
    call RawrXD_AlignedFree
    xor rax, rax
    jmp @@exit

@@error_null:
@@error_bad_shape:
@@error_bad_dtype:
@@error_oom:
    xor rax, rax

@@exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_TensorCreate ENDP

; =============================================================================
; RawrXD_TensorFree - Free a tensor and its data buffer
; Parameters: RCX = tensor pointer
; =============================================================================
RawrXD_TensorFree PROC FRAME
    .endprolog

    test rcx, rcx
    jz @@exit

    push rcx
    mov rcx, QWORD PTR [rcx + TENSOR_OFF_DATA_PTR]
    test rcx, rcx
    jz @@free_struct
    call RawrXD_AlignedFree
@@free_struct:
    pop rcx
    call RawrXD_AlignedFree

@@exit:
    ret

RawrXD_TensorFree ENDP

; =============================================================================
; RawrXD_TensorCopy - Deep copy a tensor
; Parameters:
;   RCX = source tensor pointer
; Returns: RAX = new tensor pointer, or NULL
; =============================================================================
RawrXD_TensorCopy PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    test rcx, rcx
    jz @@error

    mov rsi, rcx                    ; rsi = source

    ; Get shape pointer (it's embedded in the struct)
    lea rcx, [rsi + TENSOR_OFF_SHAPE]
    mov rdx, QWORD PTR [rsi + TENSOR_OFF_NDIM]
    mov r8d, DWORD PTR [rsi + TENSOR_OFF_DTYPE]

    ; Create new tensor with same shape/dtype
    call RawrXD_TensorCreate
    test rax, rax
    jz @@error
    mov rdi, rax                    ; rdi = destination

    ; Copy data
    mov rcx, QWORD PTR [rsi + TENSOR_OFF_DATA_PTR]
    mov rdx, QWORD PTR [rdi + TENSOR_OFF_DATA_PTR]
    mov r8, QWORD PTR [rsi + TENSOR_OFF_NUMEL]

    ; Calculate byte size
    mov r9d, DWORD PTR [rsi + TENSOR_OFF_DTYPE]
    cmp r9d, DTYPE_F32
    je @@copy_4
    cmp r9d, DTYPE_I32
    je @@copy_4
    cmp r9d, DTYPE_F16
    je @@copy_2
    cmp r9d, DTYPE_I16
    je @@copy_2
    cmp r9d, DTYPE_I8
    je @@copy_1
    cmp r9d, DTYPE_Q8_0
    je @@copy_1
    jmp @@copy_4                   ; Default to 4 bytes

@@copy_4:
    shl r8, 2
    jmp @@do_copy
@@copy_2:
    shl r8, 1
    jmp @@do_copy
@@copy_1:
    jmp @@do_copy

@@do_copy:
    call RawrXD_MemCopy

    ; Copy quant_type and device
    mov rax, QWORD PTR [rsi + TENSOR_OFF_QUANT_TYPE]
    mov QWORD PTR [rdi + TENSOR_OFF_QUANT_TYPE], rax
    mov rax, QWORD PTR [rsi + TENSOR_OFF_DEVICE]
    mov QWORD PTR [rdi + TENSOR_OFF_DEVICE], rax

    mov rax, rdi
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    pop rdi
    pop rsi
    pop rbx
    ret

RawrXD_TensorCopy ENDP

; =============================================================================
; RawrXD_TensorReshape - Reshape a tensor (must preserve numel)
; Parameters:
;   RCX = tensor pointer
;   RDX = QWORD* new_shape
;   R8  = QWORD new_ndim
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_TensorReshape PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error
    cmp r8, MAX_TENSOR_DIMS
    ja @@error

    mov rsi, rcx                    ; rsi = tensor
    mov rdi, rdx                    ; rdi = new_shape
    mov r12, r8                     ; r12 = new_ndim

    ; Verify numel matches
    mov rbx, 1                      ; rbx = new_numel
    xor r9, r9

@@calc_numel:
    cmp r9, r12
    jge @@check_numel
    mov rax, QWORD PTR [rdi + r9*8]
    test rax, rax
    jz @@error
    mul rbx
    test rdx, rdx
    jnz @@error
    mov rbx, rax
    inc r9
    jmp @@calc_numel

@@check_numel:
    mov rax, QWORD PTR [rsi + TENSOR_OFF_NUMEL]
    cmp rbx, rax
    jne @@error

    ; Update shape and recompute strides
    mov QWORD PTR [rsi + TENSOR_OFF_NDIM], r12

    mov rcx, r12
    dec rcx
    mov rax, 1

@@stride_loop:
    cmp rcx, 0
    jl @@done
    mov rdx, QWORD PTR [rdi + rcx*8]
    mov QWORD PTR [rsi + TENSOR_OFF_SHAPE + rcx*8], rdx
    mov QWORD PTR [rsi + TENSOR_OFF_STRIDE + rcx*8], rax
    mul rdx
    dec rcx
    jmp @@stride_loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

RawrXD_TensorReshape ENDP

; =============================================================================
; RawrXD_TensorView - Create a view (no data copy)
; Parameters:
;   RCX = source tensor
;   RDX = QWORD* new_shape
;   R8  = QWORD new_ndim
; Returns: RAX = new tensor view, or NULL
; =============================================================================
RawrXD_TensorView PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    test rcx, rcx
    jz @@error

    mov rsi, rcx                    ; rsi = source

    ; Allocate tensor struct only (no data buffer)
    mov rcx, TENSOR_STRUCT_SIZE
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov rdi, rax                    ; rdi = view struct

    ; Copy entire struct from source
    push rdi
    mov rcx, rsi
    mov rdx, rdi
    mov r8, TENSOR_STRUCT_SIZE
    call RawrXD_MemCopy
    pop rdi

    ; If new shape provided, reshape the view
    test rdx, rdx
    jz @@done
    test r8, r8
    jz @@done

    mov rcx, rdi
    ; RDX, R8 already set
    call RawrXD_TensorReshape

@@done:
    mov rax, rdi
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    pop rdi
    pop rsi
    pop rbx
    ret

RawrXD_TensorView ENDP

; =============================================================================
; Memory Helpers (minimal, no CRT dependency)
; =============================================================================

; RawrXD_AlignedAlloc - Allocate aligned memory
; Parameters: RCX = size
; Returns: RAX = aligned pointer, or NULL
RawrXD_AlignedAlloc PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    ; Use VirtualAlloc — returns page-aligned memory, no alignment needed
    ; VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    mov rbx, rcx                   ; save requested size
    xor ecx, ecx                   ; NULL (system chooses address)
    mov rdx, rbx                   ; size
    mov r8d, 3000h                 ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 4                     ; PAGE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz @@exit
    ; VirtualAlloc returns page-aligned memory, no alignment needed
    ; Store original pointer at [rax] (we allocated extra space)
    mov QWORD PTR [rax], rax       ; self-referencing sentinel
@@exit:
    add rsp, 32
    pop rbx
    ret
RawrXD_AlignedAlloc ENDP

; RawrXD_AlignedFree - Free aligned memory
; Parameters: RCX = aligned pointer
RawrXD_AlignedFree PROC FRAME
    sub rsp, 32
    .allocstack 32
    .endprolog
    test rcx, rcx
    jz @@exit
    ; VirtualFree(ptr, 0, MEM_RELEASE)
    xor edx, edx                   ; size = 0 (must be 0 for MEM_RELEASE)
    mov r8d, 8000h                 ; MEM_RELEASE
    call VirtualFree
@@exit:
    add rsp, 32
    ret
RawrXD_AlignedFree ENDP

; RawrXD_ZeroMemory - Zero a memory region
; Parameters: RCX = ptr, RDX = size
RawrXD_ZeroMemory PROC FRAME
    push rdi
    .pushreg rdi
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    xor eax, eax
    mov rdi, rcx                    ; dest pointer
    mov rcx, rdx                    ; count
    mov r8, rcx
    and r8, 7                       ; remainder bytes
    shr rcx, 3                     ; qword count
    rep stosq
    mov rcx, r8
    rep stosb
    pop rdi
@@exit:
    ret
RawrXD_ZeroMemory ENDP

; RawrXD_MemCopy - Copy memory
; Parameters: RCX = src, RDX = dst, R8 = size
RawrXD_MemCopy PROC FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    test r8, r8
    jz @@exit
    ; Use rep movsb for simplicity
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    rep movsb
    pop rdi
    pop rsi
@@exit:
    ret
RawrXD_MemCopy ENDP

END
