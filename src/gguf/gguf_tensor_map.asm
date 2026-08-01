; =============================================================================
; gguf_tensor_map.asm - GGUF Tensor Offset & Shape Mapping
; =============================================================================
; After GGUF_Load() reads the file header and tensor info entries,
; this module provides fast lookup of tensor data by name.
;
; Maintains a sorted index of (name_hash, offset, shape, dtype) for
; O(log n) binary search access to any weight tensor in the model.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_TENSOR_ENTRIES      EQU 512
TENSOR_NAME_HASH_SEED   EQU 5381

; Tensor map entry (32 bytes)
TENSOR_MAP_NAME_HASH    EQU 0   ; QWORD - djb2 hash of tensor name
TENSOR_MAP_DATA_OFFSET  EQU 8   ; QWORD - byte offset in GGUF data section
TENSOR_MAP_N_DIMS       EQU 16  ; DWORD - number of dimensions
TENSOR_MAP_DTYPE        EQU 20  ; DWORD - GGML_TYPE_*
TENSOR_MAP_NUMEL        EQU 24  ; QWORD - total elements
; Total: 32 bytes

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Tensor map table
align 64
g_TensorMap             DB MAX_TENSOR_ENTRIES * 32 DUP(0)
g_TensorMapCount        DQ 0
g_TensorMapSorted       DB 0

; GGUF data section base (set by GGUF_Load)
align 8
g_GGUFDataBase          DQ 0
g_GGUFMmapBase          DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; GGUF_BuildTensorMap - Build the tensor index from GGUF tensor info
;
; Parameters:
;   RCX = QWORD tensor_info_ptr  - Pointer to tensor info section
;   RDX = QWORD tensor_count    - Number of tensors
;   R8  = QWORD mmap_base       - Memory-mapped file base
;   R9  = QWORD data_offset     - Offset to data section
;
; Returns: RAX = number of tensors indexed
; =============================================================================
GGUF_BuildTensorMap PROC FRAME
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
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; tensor_info_ptr
    mov r12, rdx                    ; tensor_count
    mov QWORD PTR [g_GGUFMmapBase], r8
    mov QWORD PTR [g_GGUFDataBase], r8
    add QWORD PTR [g_GGUFDataBase], r9

    ; Limit to max entries
    cmp r12, MAX_TENSOR_ENTRIES
    jbe @@count_ok
    mov r12, MAX_TENSOR_ENTRIES
@@count_ok:

    mov QWORD PTR [g_TensorMapCount], 0
    xor r13, r13                    ; entry index
    lea r15, g_TensorMap            ; r15 = map base

@@entry_loop:
    cmp r13, r12
    jge @@sort_map

    ; Read name length
    mov r14d, DWORD PTR [rsi]
    lea rdi, [rsi + 4]             ; rdi = name string

    ; Hash the name
    mov rcx, rdi
    mov rdx, r14
    call HashString
    mov rbx, rax                    ; rbx = name hash

    ; Skip name
    lea rsi, [rsi + 4 + r14]

    ; Read n_dims
    mov r8d, DWORD PTR [rsi]
    add rsi, 4

    ; Skip shape dimensions
    lea rsi, [rsi + r8*8]

    ; Read dtype
    mov r9d, DWORD PTR [rsi]
    add rsi, 4

    ; Read offset
    mov r10, QWORD PTR [rsi]
    add rsi, 8

    ; Calculate numel from shape
    mov r11, 1
    mov rcx, rsi
    sub rcx, 8 + 4 + r8*8 + 4      ; Back to shape start
    xor rdx, rdx

@@calc_numel:
    cmp rdx, r8
    jge @@store_entry
    mov rax, QWORD PTR [rcx + rdx*8]
    mul r11
    mov r11, rax
    inc rdx
    jmp @@calc_numel

@@store_entry:
    ; Store entry in map
    mov rax, QWORD PTR [g_TensorMapCount]
    shl rax, 5                      ; * 32
    add rax, r15

    mov QWORD PTR [rax + TENSOR_MAP_NAME_HASH], rbx
    mov QWORD PTR [rax + TENSOR_MAP_DATA_OFFSET], r10
    mov DWORD PTR [rax + TENSOR_MAP_N_DIMS], r8d
    mov DWORD PTR [rax + TENSOR_MAP_DTYPE], r9d
    mov QWORD PTR [rax + TENSOR_MAP_NUMEL], r11

    inc QWORD PTR [g_TensorMapCount]
    inc r13
    jmp @@entry_loop

@@sort_map:
    ; Sort entries by name hash (simple bubble sort)
    mov r13, QWORD PTR [g_TensorMapCount]
    dec r13

@@sort_outer:
    cmp r13, 0
    jle @@done
    xor r14, r14

@@sort_inner:
    cmp r14, r13
    jge @@sort_next

    mov rax, r14
    shl rax, 5
    add rax, r15
    mov rcx, r14
    inc rcx
    shl rcx, 5
    add rcx, r15

    mov rdx, QWORD PTR [rax + TENSOR_MAP_NAME_HASH]
    mov r8, QWORD PTR [rcx + TENSOR_MAP_NAME_HASH]
    cmp rdx, r8
    jbe @@no_swap

    ; Swap entries
    push QWORD PTR [rax + 0]
    push QWORD PTR [rax + 8]
    push QWORD PTR [rax + 16]
    push QWORD PTR [rax + 24]
    mov rdx, QWORD PTR [rcx + 0]
    mov QWORD PTR [rax + 0], rdx
    mov rdx, QWORD PTR [rcx + 8]
    mov QWORD PTR [rax + 8], rdx
    mov rdx, QWORD PTR [rcx + 16]
    mov QWORD PTR [rax + 16], rdx
    mov rdx, QWORD PTR [rcx + 24]
    mov QWORD PTR [rax + 24], rdx
    pop QWORD PTR [rcx + 24]
    pop QWORD PTR [rcx + 16]
    pop QWORD PTR [rcx + 8]
    pop QWORD PTR [rcx + 0]

@@no_swap:
    inc r14
    jmp @@sort_inner

@@sort_next:
    dec r13
    jmp @@sort_outer

@@done:
    mov BYTE PTR [g_TensorMapSorted], 1
    mov rax, QWORD PTR [g_TensorMapCount]
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GGUF_BuildTensorMap ENDP

; =============================================================================
; GGUF_FindTensor - Find a tensor by name (binary search)
;
; Parameters:
;   RCX = char* name
;
; Returns: RAX = pointer to tensor map entry, or NULL
; =============================================================================
GGUF_FindTensor PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error

    ; Hash the search name
    mov rsi, rcx
    xor ecx, ecx
    mov rdx, -1
@@strlen:
    inc rdx
    cmp BYTE PTR [rsi + rdx], 0
    jne @@strlen

    mov rcx, rsi
    call HashString
    mov r12, rax                    ; r12 = target hash

    ; Binary search
    mov r13, QWORD PTR [g_TensorMapCount]
    xor r8, r8                      ; low
    mov r9, r13
    dec r9                          ; high

@@binsearch:
    cmp r8, r9
    ja @@not_found

    mov rax, r8
    add rax, r9
    shr rax, 1                      ; mid

    push rax
    shl rax, 5
    lea rdi, g_TensorMap
    add rdi, rax
    pop rax

    mov rbx, QWORD PTR [rdi + TENSOR_MAP_NAME_HASH]
    cmp r12, rbx
    je @@found
    jb @@search_left

    ; Search right
    inc rax
    mov r8, rax
    jmp @@binsearch

@@search_left:
    dec rax
    mov r9, rax
    jmp @@binsearch

@@found:
    mov rax, rdi
    jmp @@exit

@@not_found:
@@error:
    xor rax, rax

@@exit:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GGUF_FindTensor ENDP

; =============================================================================
; GGUF_GetTensorData - Get pointer to tensor weight data
;
; Parameters:
;   RCX = tensor map entry pointer (from GGUF_FindTensor)
;
; Returns: RAX = pointer to weight data, or NULL
; =============================================================================
GGUF_GetTensorData PROC FRAME
    .endprolog
    test rcx, rcx
    jz @@error

    mov rax, QWORD PTR [rcx + TENSOR_MAP_DATA_OFFSET]
    add rax, QWORD PTR [g_GGUFDataBase]
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    ret

GGUF_GetTensorData ENDP

; =============================================================================
; HashString - djb2 hash of a string
; Parameters: RCX = string, RDX = length
; Returns: RAX = 64-bit hash
; =============================================================================
HashString PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit

    mov rax, TENSOR_NAME_HASH_SEED
    xor r9, r9

@@loop:
    cmp r9, rdx
    jge @@exit
    shl rax, 5
    add rax, rax                    ; hash * 33
    movzx r8, BYTE PTR [rcx + r9]
    add rax, r8                     ; + byte
    inc r9
    jmp @@loop

@@exit:
    ret

HashString ENDP

END
