; =============================================================================
; gguf_reader.asm - GGUF Format Native Reader
; =============================================================================
; Reads GGUF (GGML Universal Format) model files directly from disk.
; No external dependencies - uses Windows file I/O APIs.
;
; GGUF Header Structure:
;   +0:  DWORD magic          - "GGUF" (0x46554747)
;   +4:  DWORD version        - Format version (3)
;   +8:  QWORD tensor_count   - Number of tensors
;  +16:  QWORD metadata_kv_count
;  +24:  (metadata KV pairs)
;  +??:  (tensor info entries)
;  +??:  (tensor data, aligned to 32 bytes)
;
; Tensor Info Entry:
;   +0:  QWORD name_len       - Length of tensor name
;   +8:  CHAR* name           - Tensor name string
;   +8+name_len: DWORD n_dims - Number of dimensions
;   +12+n_dims*8: QWORD* shape
;   +??: DWORD dtype          - GGML type
;   +??: QWORD offset         - Offset into data section
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
GGUF_MAGIC              EQU 46554747h    ; "GGUF"
GGUF_VERSION            EQU 3

; GGML quantization types
GGML_TYPE_F32           EQU 0
GGML_TYPE_F16           EQU 1
GGML_TYPE_Q4_0          EQU 2
GGML_TYPE_Q4_1          EQU 3
GGML_TYPE_Q5_0          EQU 6
GGML_TYPE_Q5_1          EQU 7
GGML_TYPE_Q8_0          EQU 8

; GGUF metadata value types
GGUF_VALUE_UINT8        EQU 0
GGUF_VALUE_INT8         EQU 1
GGUF_VALUE_UINT16       EQU 2
GGUF_VALUE_INT16        EQU 3
GGUF_VALUE_UINT32       EQU 4
GGUF_VALUE_INT32        EQU 5
GGUF_VALUE_FLOAT32      EQU 6
GGUF_VALUE_BOOL         EQU 7
GGUF_VALUE_STRING       EQU 8
GGUF_VALUE_ARRAY        EQU 9
GGUF_VALUE_UINT64       EQU 10
GGUF_VALUE_INT64        EQU 11
GGUF_VALUE_FLOAT64      EQU 12

; GGUF model architecture IDs
GGUF_ARCH_LLAMA         EQU 0
GGUF_ARCH_FALCON        EQU 1
GGUF_ARCH_BERT          EQU 2
GGUF_ARCH_NEMOTRON      EQU 3
GGUF_ARCH_GROK          EQU 4
GGUF_ARCH_STABLELM      EQU 5
GGUF_ARCH_QWEN2         EQU 6
GGUF_ARCH_QWEN2MOE      EQU 7
GGUF_ARCH_PHI3          EQU 8

; GGUF key constants
GGUF_KEY_CONTEXT_LENGTH     EQU 'context_length'
GGUF_KEY_EMBEDDING_LENGTH   EQU 'embedding_length'
GGUF_KEY_BLOCK_COUNT        EQU 'block_count'
GGUF_KEY_HEAD_COUNT         EQU 'head_count'
GGUF_KEY_HEAD_COUNT_KV      EQU 'head_count_kv'
GGUF_KEY_LAYER_NORM_RMS_EPS EQU 'layer_norm_rms_epsilon'

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; GGUF model context structure (256 bytes)
align 16
g_GGUFContext        DB 256 DUP(0)

; GGUF context field offsets
GGUF_CTX_FILE_HANDLE    EQU 0
GGUF_CTX_FILE_SIZE      EQU 8
GGUF_CTX_MMAP_PTR       EQU 16
GGUF_CTX_MMAP_SIZE      EQU 24
GGUF_CTX_TENSOR_COUNT   EQU 32
GGUF_CTX_METADATA_COUNT EQU 40
GGUF_CTX_DATA_OFFSET    EQU 48
GGUF_CTX_TENSOR_INFO    EQU 56
GGUF_CTX_ARCH           EQU 64
GGUF_CTX_N_LAYERS       EQU 72
GGUF_CTX_N_EMBED        EQU 80
GGUF_CTX_N_HEADS        EQU 88
GGUF_CTX_N_HEADS_KV     EQU 96
GGUF_CTX_N_CTX_LEN      EQU 104
GGUF_CTX_RMS_EPS        EQU 112
GGUF_CTX_N_VOCAB        EQU 120

; Error messages
align 8
szGGUFErr            DB '[GGUF] ', 0
szFileNotFound       DB 'File not found', 0
szBadMagic           DB 'Invalid GGUF magic', 0
szUnsupportedVer     DB 'Unsupported GGUF version', 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; GGUF_Load - Load a GGUF model file
;
; Parameters:
;   RCX = char* filepath - Path to .gguf file
;
; Returns: RAX = pointer to GGUF context, or NULL on failure
; =============================================================================
GGUF_Load PROC FRAME
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
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error

    mov rsi, rcx                    ; rsi = filepath

    ; --- Open file ---
    extern CreateFileA : PROC
    extern CloseHandle : PROC
    extern GetFileSize : PROC
    extern CreateFileMappingA : PROC
    extern MapViewOfFile : PROC
    extern UnmapViewOfFile : PROC
    extern ReadFile : PROC

    xor eax, eax
    mov QWORD PTR [rbp - 8], rax   ; file handle
    mov QWORD PTR [rbp - 16], rax  ; mapping handle
    mov QWORD PTR [rbp - 24], rax  ; view pointer

    ; CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
    mov rcx, rsi
    mov edx, 80000000h              ; GENERIC_READ
    mov r8d, 1                      ; FILE_SHARE_READ
    xor r9d, r9d                    ; NULL
    mov DWORD PTR [rsp + 32], 3     ; OPEN_EXISTING
    mov DWORD PTR [rsp + 40], 80h   ; FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp + 48], 0     ; NULL
    call CreateFileA
    cmp rax, -1                     ; INVALID_HANDLE_VALUE
    je @@file_error
    mov QWORD PTR [rbp - 8], rax    ; Save file handle

    ; Get file size
    mov rcx, rax
    xor edx, edx
    call GetFileSize
    mov QWORD PTR [rbp - 32], rax   ; file size

    ; CreateFileMapping
    mov rcx, QWORD PTR [rbp - 8]
    xor edx, edx                    ; NULL (default security)
    mov r8d, 4                      ; PAGE_READONLY
    xor r9d, r9d                    ; 0 (max size high)
    mov DWORD PTR [rsp + 32], 0     ; 0 (max size low = use file size)
    mov QWORD PTR [rsp + 40], 0     ; NULL (no name)
    call CreateFileMappingA
    test rax, rax
    jz @@map_error
    mov QWORD PTR [rbp - 16], rax   ; Save mapping handle

    ; MapViewOfFile
    mov rcx, rax
    mov edx, 4                      ; FILE_MAP_READ
    xor r8d, r8d                    ; 0 (offset high)
    xor r9d, r9d                    ; 0 (offset low)
    mov rax, QWORD PTR [rbp - 32]
    mov QWORD PTR [rsp + 32], rax   ; Number of bytes to map
    call MapViewOfFile
    test rax, rax
    jz @@view_error
    mov QWORD PTR [rbp - 24], rax   ; Save view pointer

    ; --- Parse GGUF header ---
    mov rdi, rax                    ; rdi = mmap pointer

    ; Check magic
    mov eax, DWORD PTR [rdi]
    cmp eax, GGUF_MAGIC
    jne @@bad_magic

    ; Check version
    mov eax, DWORD PTR [rdi + 4]
    cmp eax, GGUF_VERSION
    jne @@bad_version

    ; Read tensor count and metadata count
    mov rbx, QWORD PTR [rdi + 8]   ; tensor_count
    mov r12, QWORD PTR [rdi + 16]  ; metadata_kv_count

    ; Store in context
    lea rax, g_GGUFContext
    mov QWORD PTR [rax + GGUF_CTX_TENSOR_COUNT], rbx
    mov QWORD PTR [rax + GGUF_CTX_METADATA_COUNT], r12
    mov QWORD PTR [rax + GGUF_CTX_FILE_HANDLE], rsi
    mov r14, QWORD PTR [rbp - 32]
    mov QWORD PTR [rax + GGUF_CTX_FILE_SIZE], r14
    mov QWORD PTR [rax + GGUF_CTX_MMAP_PTR], rdi
    mov QWORD PTR [rax + GGUF_CTX_MMAP_SIZE], r14

    ; Parse metadata (skip past header)
    lea r13, [rdi + 24]            ; r13 = current position (after header)

    ; For now, skip metadata parsing and go straight to tensor info
    ; In production, this would iterate through all KV pairs
    mov rcx, r12
    xor rdx, rdx

@@skip_metadata:
    cmp rdx, rcx
    jge @@tensor_info_start
    ; Skip key string
    mov r8d, DWORD PTR [r13]
    add r13, 4
    add r13, r8
    ; Skip value (based on type)
    mov r8d, DWORD PTR [r13]
    add r13, 4
    ; Skip value data based on type
    ; (simplified - production would parse each type)
    add r13, 8                     ; Skip value (assume simple type)
    inc rdx
    jmp @@skip_metadata

@@tensor_info_start:
    ; r13 now points to tensor info section
    mov QWORD PTR [rax + GGUF_CTX_TENSOR_INFO], r13

    ; Calculate data offset (after all tensor info entries)
    mov rcx, rbx                   ; tensor_count
    xor rdx, rdx

@@calc_data_offset:
    cmp rdx, rcx
    jge @@data_offset_done
    ; Skip name length + name
    mov r8d, DWORD PTR [r13]
    add r13, 4
    add r13, r8
    ; Skip n_dims
    add r13, 4
    ; Skip shape
    mov r8d, DWORD PTR [r13 - 4]
    lea r13, [r13 + r8*8]
    ; Skip dtype
    add r13, 4
    ; Skip offset
    add r13, 8
    inc rdx
    jmp @@calc_data_offset

@@data_offset_done:
    ; Align to 32 bytes
    mov rax, r13
    sub rax, rdi
    add rax, 31
    and rax, -32
    mov QWORD PTR [rax + GGUF_CTX_DATA_OFFSET], rax

    ; Return context pointer
    lea rax, g_GGUFContext
    jmp @@exit

@@bad_magic:
    mov rax, 1
    jmp @@cleanup

@@bad_version:
    mov rax, 2
    jmp @@cleanup

@@file_error:
@@map_error:
@@view_error:
@@error:
    xor rax, rax

@@cleanup:
    push rax
    mov rcx, QWORD PTR [rbp - 24]
    test rcx, rcx
    jz @@close_mapping
    call UnmapViewOfFile
@@close_mapping:
    mov rcx, QWORD PTR [rbp - 16]
    test rcx, rcx
    jz @@close_file
    call CloseHandle
@@close_file:
    mov rcx, QWORD PTR [rbp - 8]
    test rcx, rcx
    jz @@exit_cleanup
    call CloseHandle
@@exit_cleanup:
    pop rax

@@exit:
    add rsp, 64
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GGUF_Load ENDP

; =============================================================================
; GGUF_GetTensor - Find a tensor by name in the loaded GGUF file
;
; Parameters:
;   RCX = char* name - Tensor name to find
;
; Returns: RAX = pointer to tensor info, or NULL
; =============================================================================
GGUF_GetTensor PROC FRAME
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

    mov rsi, rcx                    ; rsi = target name
    lea rdi, g_GGUFContext
    mov rbx, QWORD PTR [rdi + GGUF_CTX_TENSOR_INFO]
    mov r12, QWORD PTR [rdi + GGUF_CTX_TENSOR_COUNT]

    xor r13, r13

@@loop:
    cmp r13, r12
    jge @@not_found

    ; Read name length
    mov r8d, DWORD PTR [rbx]
    lea r9, [rbx + 4]              ; r9 = name string

    ; Compare names
    mov rcx, rsi
    mov rdx, r9
    mov r10, r8
    call RawrXD_StrCmp
    test rax, rax
    jz @@found

    ; Skip to next entry
    add rbx, 4                     ; Skip name length
    add rbx, r8                    ; Skip name
    add rbx, 4                     ; Skip n_dims
    mov r10d, DWORD PTR [rbx - 4]  ; n_dims
    lea rbx, [rbx + r10*8]         ; Skip shape
    add rbx, 4                     ; Skip dtype
    add rbx, 8                     ; Skip offset

    inc r13
    jmp @@loop

@@found:
    mov rax, rbx
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

GGUF_GetTensor ENDP

; =============================================================================
; GGUF_GetMetadata - Get a metadata value by key
;
; Parameters:
;   RCX = char* key
;   RDX = void* out_value
;   R8  = DWORD* out_type
;
; Returns: RAX = 0 on success
; =============================================================================
GGUF_GetMetadata PROC FRAME
    .endprolog
    ; Stub - production would iterate metadata KV pairs
    mov rax, 1
    ret
GGUF_GetMetadata ENDP

; =============================================================================
; GGUF_MapWeights - Get pointer to weight data for a tensor
;
; Parameters:
;   RCX = tensor info pointer (from GGUF_GetTensor)
;
; Returns: RAX = pointer to weight data, or NULL
; =============================================================================
GGUF_MapWeights PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    test rcx, rcx
    jz @@error

    mov rbx, rcx

    ; Skip name length + name
    mov eax, DWORD PTR [rbx]
    lea rbx, [rbx + 4 + rax]

    ; Skip n_dims
    add rbx, 4
    mov r8d, DWORD PTR [rbx - 4]

    ; Skip shape
    lea rbx, [rbx + r8*8]

    ; Skip dtype
    add rbx, 4

    ; Read offset
    mov rax, QWORD PTR [rbx]

    ; Add data section base
    lea rcx, g_GGUFContext
    add rax, QWORD PTR [rcx + GGUF_CTX_MMAP_PTR]
    add rax, QWORD PTR [rcx + GGUF_CTX_DATA_OFFSET]

    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    pop rbx
    ret

GGUF_MapWeights ENDP

; =============================================================================
; RawrXD_StrCmp - String comparison (null-terminated, length-limited)
; Parameters: RCX = str1, RDX = str2, R8 = max_len
; Returns: RAX = 0 if equal
; =============================================================================
RawrXD_StrCmp PROC FRAME
    .endprolog
    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    xor eax, eax

@@loop:
    test r8, r8
    jz @@equal
    mov al, BYTE PTR [rcx]
    mov bl, BYTE PTR [rdx]
    cmp al, bl
    jne @@not_equal
    test al, al
    jz @@equal
    inc rcx
    inc rdx
    dec r8
    jmp @@loop

@@equal:
    xor eax, eax
    ret

@@not_equal:
    mov eax, 1
    ret

@@error:
    mov eax, -1
    ret

RawrXD_StrCmp ENDP

END
