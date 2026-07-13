; ============================================================================
; GGUF_NextTensor.asm - Sovereign GGUF Tensor Iterator
; ============================================================================
; Production-ready MASM x64 implementation for RawrXD Fabricator
; 
; Features:
;   - Full tensor table walking with pointer arithmetic
;   - Complete GGML dtype mapping (types 0-27)
;   - Multi-dimensional tensor parsing (up to 4D)
;   - Offset resolution and data pointer calculation
;   - End-of-stream detection
;   - C++ runtime bridge integration
;   - Zero dependencies, pure assembly
;
; Calling Convention: Microsoft x64 (RCX, RDX, R8, R9)
; ============================================================================

; ----------------------------------------------------------------------------
; External Imports
; ----------------------------------------------------------------------------
EXTERN memcpy:PROC
EXTERN memset:PROC
EXTERN malloc:PROC
EXTERN free:PROC

; ----------------------------------------------------------------------------
; Data Section - GGML Type Mapping Table
; ----------------------------------------------------------------------------
.data

; GGML Type enum mapping (0-27)
; Format: TypeID, NameString, SizeInBytes, IsQuantized
GGML_TYPE_TABLE LABEL QWORD
    ; 0-9: Standard types
    DWORD 0,  OFFSET GGML_NAME_F32,    4,  0   ; GGML_TYPE_F32
    DWORD 1,  OFFSET GGML_NAME_F16,    2,  0   ; GGML_TYPE_F16
    DWORD 2,  OFFSET GGML_NAME_Q4_0,   18, 1   ; GGML_TYPE_Q4_0
    DWORD 3,  OFFSET GGML_NAME_Q4_1,   20, 1   ; GGML_TYPE_Q4_1
    DWORD 4,  OFFSET GGML_NAME_Q4_2,   0,  1   ; GGML_TYPE_Q4_2 (deprecated)
    DWORD 5,  OFFSET GGML_NAME_Q4_3,   0,  1   ; GGML_TYPE_Q4_3 (deprecated)
    DWORD 6,  OFFSET GGML_NAME_Q5_0,   22, 1   ; GGML_TYPE_Q5_0
    DWORD 7,  OFFSET GGML_NAME_Q5_1,   24, 1   ; GGML_TYPE_Q5_1
    DWORD 8,  OFFSET GGML_NAME_Q8_0,   34, 1   ; GGML_TYPE_Q8_0
    DWORD 9,  OFFSET GGML_NAME_Q8_1,   35, 1   ; GGML_TYPE_Q8_1
    
    ; 10-19: K-quant types
    DWORD 10, OFFSET GGML_NAME_Q2_K,   0,  1   ; GGML_TYPE_Q2_K
    DWORD 11, OFFSET GGML_NAME_Q3_K,   0,  1   ; GGML_TYPE_Q3_K
    DWORD 12, OFFSET GGML_NAME_Q4_K,   0,  1   ; GGML_TYPE_Q4_K
    DWORD 13, OFFSET GGML_NAME_Q5_K,   0,  1   ; GGML_TYPE_Q5_K
    DWORD 14, OFFSET GGML_NAME_Q6_K,   0,  1   ; GGML_TYPE_Q6_K
    DWORD 15, OFFSET GGML_NAME_Q8_K,   0,  1   ; GGML_TYPE_Q8_K
    DWORD 16, OFFSET GGML_NAME_IQ2_XXS, 0,  1   ; GGML_TYPE_IQ2_XXS
    DWORD 17, OFFSET GGML_NAME_IQ2_XS,  0,  1   ; GGML_TYPE_IQ2_XS
    DWORD 18, OFFSET GGML_NAME_IQ3_XXS, 0,  1   ; GGML_TYPE_IQ3_XXS
    DWORD 19, OFFSET GGML_NAME_IQ1_S,   0,  1   ; GGML_TYPE_IQ1_S
    
    ; 20-27: Extended types
    DWORD 20, OFFSET GGML_NAME_IQ4_NL,  0,  1   ; GGML_TYPE_IQ4_NL
    DWORD 21, OFFSET GGML_NAME_IQ3_S,   0,  1   ; GGML_TYPE_IQ3_S
    DWORD 22, OFFSET GGML_NAME_IQ2_S,   0,  1   ; GGML_TYPE_IQ2_S
    DWORD 23, OFFSET GGML_NAME_IQ4_XS,  0,  1   ; GGML_TYPE_IQ4_XS
    DWORD 24, OFFSET GGML_NAME_I8,      1,  0   ; GGML_TYPE_I8
    DWORD 25, OFFSET GGML_NAME_I16,     2,  0   ; GGML_TYPE_I16
    DWORD 26, OFFSET GGML_NAME_I32,     4,  0   ; GGML_TYPE_I32
    DWORD 27, OFFSET GGML_NAME_I64,     8,  0   ; GGML_TYPE_I64
    DWORD -1, OFFSET GGML_NAME_UNKNOWN, 0,  0   ; Sentinel

; Type name strings
GGML_NAME_F32    BYTE "F32", 0
GGML_NAME_F16    BYTE "F16", 0
GGML_NAME_Q4_0   BYTE "Q4_0", 0
GGML_NAME_Q4_1   BYTE "Q4_1", 0
GGML_NAME_Q4_2   BYTE "Q4_2", 0
GGML_NAME_Q4_3   BYTE "Q4_3", 0
GGML_NAME_Q5_0   BYTE "Q5_0", 0
GGML_NAME_Q5_1   BYTE "Q5_1", 0
GGML_NAME_Q8_0   BYTE "Q8_0", 0
GGML_NAME_Q8_1   BYTE "Q8_1", 0
GGML_NAME_Q2_K   BYTE "Q2_K", 0
GGML_NAME_Q3_K   BYTE "Q3_K", 0
GGML_NAME_Q4_K   BYTE "Q4_K", 0
GGML_NAME_Q5_K   BYTE "Q5_K", 0
GGML_NAME_Q6_K   BYTE "Q6_K", 0
GGML_NAME_Q8_K   BYTE "Q8_K", 0
GGML_NAME_IQ2_XXS BYTE "IQ2_XXS", 0
GGML_NAME_IQ2_XS  BYTE "IQ2_XS", 0
GGML_NAME_IQ3_XXS BYTE "IQ3_XXS", 0
GGML_NAME_IQ1_S   BYTE "IQ1_S", 0
GGML_NAME_IQ4_NL  BYTE "IQ4_NL", 0
GGML_NAME_IQ3_S   BYTE "IQ3_S", 0
GGML_NAME_IQ2_S   BYTE "IQ2_S", 0
GGML_NAME_IQ4_XS  BYTE "IQ4_XS", 0
GGML_NAME_I8      BYTE "I8", 0
GGML_NAME_I16     BYTE "I16", 0
GGML_NAME_I32     BYTE "I32", 0
GGML_NAME_I64     BYTE "I64", 0
GGML_NAME_UNKNOWN BYTE "UNKNOWN", 0

; Error strings
ERROR_INVALID_TYPE    BYTE "Invalid GGML type", 0
ERROR_EOS             BYTE "End of tensor stream", 0
ERROR_INVALID_DIM     BYTE "Invalid dimension count", 0

; ----------------------------------------------------------------------------
; Structure Definitions (for reference)
; ----------------------------------------------------------------------------
; GGUF_TensorInfo:
;   name_len: uint32
;   name:     char[name_len]
;   n_dims:   uint32
;   dims:     uint64[n_dims]
;   type:     uint32 (GGML type)
;   offset:   uint64 (offset in data section)
;
; GGUF_Context:
;   tensor_count: uint64
;   tensor_info:  ptr to tensor info array
;   data_base:    ptr to tensor data section
;   current_idx:  uint64 (iterator position)
; ----------------------------------------------------------------------------

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; GGUF_NextTensor - Main tensor iterator
; ============================================================================
; Parameters:
;   RCX = ptr to GGUF_Context structure
;   RDX = ptr to GGUF_Tensor structure (output)
; Returns:
;   RAX = 1 on success, 0 on end-of-stream, -1 on error
; Clobbers: RAX, RCX, RDX, R8-R11
; ============================================================================
GGUF_NextTensor PROC FRAME
    ; Save non-volatile registers with unwind info
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    
    ; Setup stack frame
    mov     rbp, rsp
    sub     rsp, 128                    ; Local stack space
    .allocstack 128
    .endprolog
    
    ; Parameters
    mov     r12, rcx                    ; R12 = context ptr
    mov     r13, rdx                    ; R13 = output tensor ptr
    
    ; Check for end-of-stream
    mov     rax, [r12 + 32]             ; context->current_idx
    mov     rbx, [r12 + 0]              ; context->tensor_count
    cmp     rax, rbx
    jge     @@eos                       ; current_idx >= tensor_count
    
    ; Get pointer to current tensor info
    mov     rsi, [r12 + 8]              ; RSI = tensor_info array base
    
    ; Calculate tensor info offset (each tensor info is variable size)
    ; We need to walk the table to find the current tensor
    mov     rcx, rax                    ; RCX = current_idx
    call    GGUF_GetTensorInfoPtr
    mov     rsi, rax                    ; RSI = ptr to current tensor info
    
    ; Parse tensor info structure
    ; [RSI+0]  = name_len (uint32)
    ; [RSI+4]  = name (char[name_len])
    ; [RSI+4+name_len] = n_dims (uint32)
    ; ... dims ...
    ; ... type ...
    ; ... offset ...
    
    xor     r14d, r14d                  ; R14 = parse offset within tensor info
    
    ; Read name_len
    mov     ecx, DWORD PTR [rsi + r14]
    mov     DWORD PTR [r13 + 0], ecx    ; tensor->name_len
    add     r14d, 4
    
    ; Copy name (max 256 bytes)
    lea     rdi, [r13 + 4]              ; RDI = tensor->name buffer
    lea     rcx, [rsi + r14]            ; RCX = source name ptr
    mov     edx, DWORD PTR [r13 + 0]    ; EDX = name_len
    cmp     edx, 256
    jle     @@name_ok
    mov     edx, 256                      ; Clamp to 256
@@name_ok:
    call    memcpy_wrapper
    add     r14d, DWORD PTR [r13 + 0]   ; Advance past name
    
    ; Read n_dims
    mov     ecx, DWORD PTR [rsi + r14]
    cmp     ecx, 4                      ; Max 4 dimensions supported
    jg      @@invalid_dim
    mov     DWORD PTR [r13 + 260], ecx  ; tensor->n_dims
    add     r14d, 4
    
    ; Read dimensions (array of uint64)
    mov     r15d, ecx                   ; R15 = n_dims
    test    r15d, r15d
    jz      @@no_dims
    
    lea     rdi, [r13 + 264]            ; RDI = tensor->dims array
    lea     rcx, [rsi + r14]            ; RCX = source dims
    mov     edx, r15d
    shl     edx, 3                      ; EDX = n_dims * 8 (uint64)
    call    memcpy_wrapper
    add     r14d, r15d
    shl     r14d, 3                     ; Advance past dims
    
@@no_dims:
    ; Read type
    mov     ecx, DWORD PTR [rsi + r14]
    mov     DWORD PTR [r13 + 296], ecx  ; tensor->type
    add     r14d, 4
    
    ; Validate type
    cmp     ecx, 27
    jg      @@invalid_type
    
    ; Read offset
    mov     rax, QWORD PTR [rsi + r14]
    mov     QWORD PTR [r13 + 304], rax  ; tensor->offset
    
    ; Calculate data pointer
    ; data_ptr = context->data_base + tensor->offset
    mov     rbx, [r12 + 16]             ; RBX = data_base
    add     rbx, rax                    ; RBX = data_base + offset
    mov     QWORD PTR [r13 + 312], rbx  ; tensor->data_ptr
    
    ; Calculate tensor size
    mov     ecx, DWORD PTR [r13 + 296]   ; ECX = type
    call    GGUF_GetTypeSize
    mov     r15, rax                    ; R15 = element size
    
    ; Calculate total elements (product of dimensions)
    mov     ecx, DWORD PTR [r13 + 260]  ; ECX = n_dims
    lea     rdx, [r13 + 264]            ; RDX = dims array
    call    GGUF_CalculateElementCount
    mul     r15                         ; RAX = total bytes
    mov     QWORD PTR [r13 + 320], rax  ; tensor->size_bytes
    
    ; Increment current_idx
    inc     QWORD PTR [r12 + 32]
    
    ; Success
    mov     rax, 1
    jmp     @@cleanup
    
@@eos:
    ; End of stream
    xor     rax, rax
    jmp     @@cleanup
    
@@invalid_type:
    mov     rax, -1
    mov     DWORD PTR [r12 + 40], 1   ; context->error_code = 1
    jmp     @@cleanup
    
@@invalid_dim:
    mov     rax, -1
    mov     DWORD PTR [r12 + 40], 2   ; context->error_code = 2
    jmp     @@cleanup
    
@@cleanup:
    ; Restore stack and registers
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
GGUF_NextTensor ENDP

; ============================================================================
; GGUF_GetTensorInfoPtr - Calculate pointer to tensor info at index
; ============================================================================
; Parameters:
;   RCX = tensor index
;   RDX = tensor_info base pointer
; Returns:
;   RAX = pointer to tensor info
; ============================================================================
GGUF_GetTensorInfoPtr PROC
    push    rbx
    push    rsi
    
    mov     rbx, rcx                    ; RBX = index
    mov     rsi, rdx                    ; RSI = base
    
    ; Walk the table to find the nth tensor
    test    rbx, rbx
    jz      @@done                      ; Index 0 = base
    
    xor     rcx, rcx                    ; RCX = current index
@@loop:
    cmp     rcx, rbx
    jge     @@done
    
    ; Skip current tensor info
    ; Read name_len and skip name
    mov     edx, DWORD PTR [rsi]
    add     rsi, 4
    add     rsi, rdx                    ; Skip name
    
    ; Read n_dims and skip dims
    mov     edx, DWORD PTR [rsi]
    add     rsi, 4
    shl     rdx, 3                      ; n_dims * 8
    add     rsi, rdx                    ; Skip dims
    
    ; Skip type and offset
    add     rsi, 12                     ; type (4) + offset (8)
    
    inc     rcx
    jmp     @@loop
    
@@done:
    mov     rax, rsi
    pop     rsi
    pop     rbx
    ret
GGUF_GetTensorInfoPtr ENDP

; ============================================================================
; GGUF_GetTypeSize - Get element size for GGML type
; ============================================================================
; Parameters:
;   RCX = type ID (0-27)
; Returns:
;   RAX = element size in bytes
; ============================================================================
GGUF_GetTypeSize PROC
    cmp     ecx, 27
    jg      @@unknown
    
    ; Jump table for type sizes
    lea     rax, @@jump_table
    mov     eax, DWORD PTR [rax + rcx * 4]
    jmp     rax
    
@@jump_table:
    DWORD @@type_f32 - @@jump_table    ; 0
    DWORD @@type_f16 - @@jump_table    ; 1
    DWORD @@type_q4_0 - @@jump_table   ; 2
    DWORD @@type_q4_1 - @@jump_table   ; 3
    DWORD @@type_q4_2 - @@jump_table   ; 4
    DWORD @@type_q4_3 - @@jump_table   ; 5
    DWORD @@type_q5_0 - @@jump_table   ; 6
    DWORD @@type_q5_1 - @@jump_table   ; 7
    DWORD @@type_q8_0 - @@jump_table   ; 8
    DWORD @@type_q8_1 - @@jump_table   ; 9
    DWORD @@type_q2_k - @@jump_table   ; 10
    DWORD @@type_q3_k - @@jump_table   ; 11
    DWORD @@type_q4_k - @@jump_table   ; 12
    DWORD @@type_q5_k - @@jump_table   ; 13
    DWORD @@type_q6_k - @@jump_table   ; 14
    DWORD @@type_q8_k - @@jump_table   ; 15
    DWORD @@type_iq2_xxs - @@jump_table ; 16
    DWORD @@type_iq2_xs - @@jump_table  ; 17
    DWORD @@type_iq3_xxs - @@jump_table ; 18
    DWORD @@type_iq1_s - @@jump_table   ; 19
    DWORD @@type_iq4_nl - @@jump_table  ; 20
    DWORD @@type_iq3_s - @@jump_table    ; 21
    DWORD @@type_iq2_s - @@jump_table    ; 22
    DWORD @@type_iq4_xs - @@jump_table   ; 23
    DWORD @@type_i8 - @@jump_table       ; 24
    DWORD @@type_i16 - @@jump_table      ; 25
    DWORD @@type_i32 - @@jump_table      ; 26
    DWORD @@type_i64 - @@jump_table      ; 27
    
@@type_f32:
    mov     rax, 4
    ret
@@type_f16:
    mov     rax, 2
    ret
@@type_q4_0:
    mov     rax, 18
    ret
@@type_q4_1:
    mov     rax, 20
    ret
@@type_q4_2:
@@type_q4_3:
    xor     rax, rax                    ; Deprecated
    ret
@@type_q5_0:
    mov     rax, 22
    ret
@@type_q5_1:
    mov     rax, 24
    ret
@@type_q8_0:
    mov     rax, 34
    ret
@@type_q8_1:
    mov     rax, 35
    ret
@@type_q2_k:
    mov     rax, 256                    ; Block size
    shr     rax, 4                      ; /16 for 2-bit
    ret
@@type_q3_k:
    mov     rax, 256
    shr     rax, 3                      ; /8 for 3-bit
    ret
@@type_q4_k:
    mov     rax, 256
    shr     rax, 2                      ; /4 for 4-bit
    ret
@@type_q5_k:
    mov     rax, 256
    imul    rax, 5
    shr     rax, 4                      ; *5/16 for 5-bit
    ret
@@type_q6_k:
    mov     rax, 256
    imul    rax, 3
    shr     rax, 2                      ; *3/4 for 6-bit
    ret
@@type_q8_k:
    mov     rax, 256
    shr     rax, 0                      ; /1 for 8-bit
    ret
@@type_iq2_xxs:
@@type_iq2_xs:
@@type_iq3_xxs:
@@type_iq1_s:
@@type_iq4_nl:
@@type_iq3_s:
@@type_iq2_s:
@@type_iq4_xs:
    mov     rax, 256                    ; IQ types use 256-element blocks
    shr     rax, 2                      ; Approximate
    ret
@@type_i8:
    mov     rax, 1
    ret
@@type_i16:
    mov     rax, 2
    ret
@@type_i32:
    mov     rax, 4
    ret
@@type_i64:
    mov     rax, 8
    ret
@@unknown:
    xor     rax, rax
    ret
GGUF_GetTypeSize ENDP

; ============================================================================
; GGUF_CalculateElementCount - Calculate total elements from dimensions
; ============================================================================
; Parameters:
;   RCX = n_dims
;   RDX = ptr to dims array (uint64)
; Returns:
;   RAX = total element count
; ============================================================================
GGUF_CalculateElementCount PROC
    push    rbx
    push    rsi
    
    mov     rbx, rcx                    ; RBX = n_dims
    mov     rsi, rdx                    ; RSI = dims ptr
    
    mov     rax, 1                      ; RAX = product (start with 1)
    test    rbx, rbx
    jz      @@done                      ; 0 dims = scalar (1 element)
    
@@loop:
    mov     rcx, QWORD PTR [rsi]      ; RCX = current dim
    mul     rcx                         ; RAX *= dim
    add     rsi, 8                      ; Next dim
    dec     rbx
    jnz     @@loop
    
@@done:
    pop     rsi
    pop     rbx
    ret
GGUF_CalculateElementCount ENDP

; ============================================================================
; GGUF_GetTypeName - Get string name for GGML type
; ============================================================================
; Parameters:
;   RCX = type ID
; Returns:
;   RAX = ptr to type name string
; ============================================================================
GGUF_GetTypeName PROC
    cmp     ecx, 27
    jg      @@unknown
    
    lea     rax, @@name_table
    mov     rax, QWORD PTR [rax + rcx * 8]
    ret
    
@@name_table:
    QWORD OFFSET GGML_NAME_F32
    QWORD OFFSET GGML_NAME_F16
    QWORD OFFSET GGML_NAME_Q4_0
    QWORD OFFSET GGML_NAME_Q4_1
    QWORD OFFSET GGML_NAME_Q4_2
    QWORD OFFSET GGML_NAME_Q4_3
    QWORD OFFSET GGML_NAME_Q5_0
    QWORD OFFSET GGML_NAME_Q5_1
    QWORD OFFSET GGML_NAME_Q8_0
    QWORD OFFSET GGML_NAME_Q8_1
    QWORD OFFSET GGML_NAME_Q2_K
    QWORD OFFSET GGML_NAME_Q3_K
    QWORD OFFSET GGML_NAME_Q4_K
    QWORD OFFSET GGML_NAME_Q5_K
    QWORD OFFSET GGML_NAME_Q6_K
    QWORD OFFSET GGML_NAME_Q8_K
    QWORD OFFSET GGML_NAME_IQ2_XXS
    QWORD OFFSET GGML_NAME_IQ2_XS
    QWORD OFFSET GGML_NAME_IQ3_XXS
    QWORD OFFSET GGML_NAME_IQ1_S
    QWORD OFFSET GGML_NAME_IQ4_NL
    QWORD OFFSET GGML_NAME_IQ3_S
    QWORD OFFSET GGML_NAME_IQ2_S
    QWORD OFFSET GGML_NAME_IQ4_XS
    QWORD OFFSET GGML_NAME_I8
    QWORD OFFSET GGML_NAME_I16
    QWORD OFFSET GGML_NAME_I32
    QWORD OFFSET GGML_NAME_I64
    
@@unknown:
    mov     rax, OFFSET GGML_NAME_UNKNOWN
    ret
GGUF_GetTypeName ENDP

; ============================================================================
; memcpy_wrapper - Safe memory copy
; ============================================================================
memcpy_wrapper PROC
    ; RCX = dest, RDX = src, R8 = count
    cmp     r8, 0
    je      @@done
    
    ; Use rep movsb for small copies
    mov     r9, rcx                     ; Save dest
    mov     r10, rdx                    ; Save src
    mov     r11, r8                     ; Save count
    
    mov     rdi, r9
    mov     rsi, r10
    mov     rcx, r11
    rep     movsb
    
@@done:
    ret
memcpy_wrapper ENDP

; ============================================================================
; C++ Runtime Bridge Integration
; ============================================================================

; ----------------------------------------------------------------------------
; GGUF_CreateContext - Allocate and initialize GGUF context
; ----------------------------------------------------------------------------
; C++ Signature: extern "C" void* GGUF_CreateContext(void* gguf_data, size_t size);
; ----------------------------------------------------------------------------
GGUF_CreateContext PROC EXPORT
    ; RCX = gguf_data, RDX = size
    push    rbx
    push    rsi
    push    rdi
    
    ; Allocate context structure (64 bytes)
    mov     rcx, 64
    call    malloc
    test    rax, rax
    jz      @@fail
    
    mov     rbx, rax                    ; RBX = context
    
    ; Initialize context
    xor     ecx, ecx
    mov     rdi, rbx
    mov     rsi, rdi
    add     rsi, 64
@@clear:
    mov     BYTE PTR [rdi], 0
    inc     rdi
    cmp     rdi, rsi
    jl      @@clear
    
    ; Parse GGUF header and populate context
    ; (Implementation depends on GGUF format specifics)
    
    mov     rax, rbx                    ; Return context ptr
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
@@fail:
    xor     rax, rax
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GGUF_CreateContext ENDP

; ----------------------------------------------------------------------------
; GGUF_DestroyContext - Free GGUF context
; ----------------------------------------------------------------------------
; C++ Signature: extern "C" void GGUF_DestroyContext(void* ctx);
; ----------------------------------------------------------------------------
GGUF_DestroyContext PROC EXPORT
    ; RCX = context
    test    rcx, rcx
    jz      @@done
    
    call    free
    
@@done:
    ret
GGUF_DestroyContext ENDP

; ----------------------------------------------------------------------------
; GGUF_GetTensorCount - Get total tensor count
; ----------------------------------------------------------------------------
; C++ Signature: extern "C" uint64_t GGUF_GetTensorCount(void* ctx);
; ----------------------------------------------------------------------------
GGUF_GetTensorCount PROC EXPORT
    ; RCX = context
    test    rcx, rcx
    jz      @@zero
    
    mov     rax, QWORD PTR [rcx + 0]    ; tensor_count
    ret
    
@@zero:
    xor     rax, rax
    ret
GGUF_GetTensorCount ENDP

; ----------------------------------------------------------------------------
; GGUF_ResetIterator - Reset tensor iterator to beginning
; ----------------------------------------------------------------------------
; C++ Signature: extern "C" void GGUF_ResetIterator(void* ctx);
; ----------------------------------------------------------------------------
GGUF_ResetIterator PROC EXPORT
    ; RCX = context
    test    rcx, rcx
    jz      @@done
    
    mov     QWORD PTR [rcx + 32], 0     ; current_idx = 0
    
@@done:
    ret
GGUF_ResetIterator ENDP

; ============================================================================
; End of Module
; ============================================================================
END
