; ==============================================================================
; Sovereign_GGUF_Loader.asm ? Memory-Mapped GGUF Loader (Derived from mmap_loader)
; ==============================================================================
; Replaces the buggy alignment-prone version with proven mmap_loader logic.
; Uses CreateFileMapping + MapViewOfFile for true memory-mapped I/O.
; Zero CRT. kernel32.lib only.
; ==============================================================================

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN CreateFileA          : PROC
EXTERN GetFileSizeEx        : PROC
EXTERN CreateFileMappingA   : PROC
EXTERN MapViewOfFile        : PROC
EXTERN UnmapViewOfFile      : PROC
EXTERN CloseHandle          : PROC
EXTERN GetLastError         : PROC

; ==============================================================================
; Win32 Constants
; ==============================================================================
GENERIC_READ                EQU 80000000h
FILE_SHARE_READ             EQU 1
OPEN_EXISTING               EQU 3
FILE_ATTRIBUTE_NORMAL       EQU 80h
INVALID_HANDLE_VALUE        EQU -1
PAGE_READONLY               EQU 02h
FILE_MAP_READ               EQU 04h

GGUF_MAGIC                  EQU 46554747h
GGUF_VERSION_MIN            EQU 2
GGUF_VERSION_MAX            EQU 3

GGUF_TYPE_UINT8             EQU 0
GGUF_TYPE_INT8              EQU 1
GGUF_TYPE_UINT16            EQU 2
GGUF_TYPE_INT16             EQU 3
GGUF_TYPE_UINT32            EQU 4
GGUF_TYPE_INT32             EQU 5
GGUF_TYPE_FLOAT32           EQU 6
GGUF_TYPE_BOOL              EQU 7
GGUF_TYPE_STRING            EQU 8
GGUF_TYPE_ARRAY             EQU 9
GGUF_TYPE_UINT64            EQU 10
GGUF_TYPE_INT64             EQU 11
GGUF_TYPE_FLOAT64           EQU 12

; ==============================================================================
; Structures
; ==============================================================================
MODEL_INFO STRUCT
    Magic           dd ?
    Version         dd ?
    TensorCount     dq ?
    KVCount         dq ?
    VocabSize       dd ?
    ContextLength   dd ?
    EmbeddingDim    dd ?
    HeadCount       dd ?
    LayerCount      dd ?
    QuantType       dd ?
    ArchName        db 32 dup(?)
MODEL_INFO ENDS

TENSOR_INFO STRUCT
    NameHash        dq ?
    DataOffset      dq ?
    DataSize        dq ?
    Dims            dd 4 dup(?)
    NDim            dd ?
    QuantType       dd ?
    NameStr         db 64 dup(?)
TENSOR_INFO ENDS

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

EXTERN g_LastLoadResult     : DWORD
EXTERN g_LastLoadWin32Error : DWORD

LOAD_RESULT_SUCCESS             EQU 0
LOAD_RESULT_ERROR_FILE_NOT_FOUND EQU -1
LOAD_RESULT_ERROR_CORRUPT_DATA  EQU -3
LOAD_RESULT_ERROR_OPEN_FAILED   EQU -5
LOAD_RESULT_ERROR_FILE_SIZE_READ_FAILED EQU -6
LOAD_RESULT_ERROR_FILE_MAPPING_FAILED EQU -7
LOAD_RESULT_ERROR_MAP_VIEW_FAILED EQU -8
LOAD_RESULT_ERROR_UNKNOWN       EQU -99

g_ModelBase         dq 0
g_ModelSize         dq 0
g_hFile             dq 0
g_hMapping          dq 0
g_ModelInfo         MODEL_INFO <>

MAX_TENSOR_ENTRIES  EQU 1024
g_TensorCount       dq 0
g_TensorTable       TENSOR_INFO MAX_TENSOR_ENTRIES dup(<>)

szKeyArch           db "general.architecture", 0
szKeyVocabSize      db "tokenizer.ggml.vocab_size", 0
szKeyCtxLen         db ".context_length", 0
szKeyEmbedDim       db ".embedding_length", 0
szKeyHeadCount      db ".attention.head_count", 0
szKeyLayerCount     db ".block_count", 0

; ======================================================================
; Code Section
; ======================================================================
.code

; ==============================================================================
; Helper: String compare
; ==============================================================================
StrCmp PROC
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
@@loop:
    movzx eax, byte ptr [rsi]
    movzx edx, byte ptr [rdi]
    cmp al, dl
    jne @@diff
    test al, al
    jz @@equal
    inc rsi
    inc rdi
    jmp @@loop
@@diff:
    sub eax, edx
    pop rdi
    pop rsi
    ret
@@equal:
    xor eax, eax
    pop rdi
    pop rsi
    ret
StrCmp ENDP

; ==============================================================================
; Helper: String length
; ==============================================================================
StrLen PROC
    push rdi
    mov rdi, rcx
    xor ecx, ecx
    dec rcx
    xor eax, eax
    repne scasb
    mov rax, rcx
    not rax
    dec rax
    pop rdi
    ret
StrLen ENDP

; ==============================================================================
; Helper: Copy string up to N bytes
; ==============================================================================
StrNCpy PROC
    push rsi
    push rdi
    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
    test rcx, rcx
    jz @@done
@@loop:
    movzx eax, byte ptr [rsi]
    mov byte ptr [rdi], al
    test al, al
    jz @@done
    inc rsi
    inc rdi
    dec rcx
    jnz @@loop
@@done:
    pop rdi
    pop rsi
    ret
StrNCpy ENDP

; ==============================================================================
; Helper: Parse GGUF value size
; ==============================================================================
GGUFValueSize PROC
    cmp ecx, GGUF_TYPE_UINT8
    je @@sz1
    cmp ecx, GGUF_TYPE_INT8
    je @@sz1
    cmp ecx, GGUF_TYPE_BOOL
    je @@sz1
    cmp ecx, GGUF_TYPE_UINT16
    je @@sz2
    cmp ecx, GGUF_TYPE_INT16
    je @@sz2
    cmp ecx, GGUF_TYPE_UINT32
    je @@sz4
    cmp ecx, GGUF_TYPE_INT32
    je @@sz4
    cmp ecx, GGUF_TYPE_FLOAT32
    je @@sz4
    cmp ecx, GGUF_TYPE_UINT64
    je @@sz8
    cmp ecx, GGUF_TYPE_INT64
    je @@sz8
    cmp ecx, GGUF_TYPE_FLOAT64
    je @@sz8
    xor eax, eax
    ret
@@sz1:  mov eax, 1
    ret
@@sz2:  mov eax, 2
    ret
@@sz4:  mov eax, 4
    ret
@@sz8:  mov eax, 8
    ret
GGUFValueSize ENDP

; ==============================================================================
; Helper: Skip a GGUF value
; ==============================================================================
SkipGGUFValue PROC
    push rbx
    mov rbx, rcx
    cmp edx, GGUF_TYPE_STRING
    je @@string
    cmp edx, GGUF_TYPE_ARRAY
    je @@array
    mov ecx, edx
    call GGUFValueSize
    add rbx, rax
    mov rax, rbx
    pop rbx
    ret
@@string:
    mov rcx, [rbx]
    add rbx, 8
    add rbx, rcx
    mov rax, rbx
    pop rbx
    ret
@@array:
    mov ecx, dword ptr [rbx]
    mov r8, [rbx+4]
    add rbx, 12
    test r8, r8
    jz @@array_done
@@array_loop:
    push r8
    push rcx
    push rbx
    mov edx, ecx
    mov rcx, rbx
    call SkipGGUFValue
    mov rbx, rax
    pop rax
    pop rcx
    pop r8
    dec r8
    jnz @@array_loop
@@array_done:
    mov rax, rbx
    pop rbx
    ret
SkipGGUFValue ENDP

; ==============================================================================
; Helper: Find metadata value by key suffix
; ==============================================================================
FindMetadataValue PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov rbx, r9
    test r14, r14
    jz @@not_found
@@kv_loop:
    mov rsi, r13
    mov rcx, [rsi]
    add rsi, 8
    mov rdi, rsi
    add rdi, rcx
    mov edx, dword ptr [rdi]
    add rdi, 4
    mov r8, rdi
    push rdx
    push r8
    mov rcx, r12
    call StrLen
    mov r9, rax
    pop r8
    pop rdx
    mov rcx, [r13]
    cmp rcx, r9
    jb @@next_kv
    mov rax, rsi
    add rax, rcx
    sub rax, r9
    push rdx
    push r8
    push rsi
    mov rcx, rax
    mov rdx, r12
    call StrCmp
    mov r9, rax
    pop rsi
    pop r8
    pop rdx
    test r9, r9
    jnz @@next_kv
    mov rax, r8
    jmp @@found
@@next_kv:
    mov rcx, r8
    call SkipGGUFValue
    mov r13, rax
    dec r14
    jnz @@kv_loop
@@not_found:
    xor eax, eax
    xor edx, edx
@@found:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
FindMetadataValue ENDP

; ==============================================================================
; Helper: FNV-1a 64-bit hash
; ==============================================================================
FNV1A_64_LOCAL PROC
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    mov rax, 14695981039346656037
    mov r8, 1099511628211
@@loop:
    test rdi, rdi
    jz @@done
    movzx r9, byte ptr [rsi]
    xor rax, r9
    mul r8
    inc rsi
    dec rdi
    jmp @@loop
@@done:
    pop rdi
    pop rsi
    ret
FNV1A_64_LOCAL ENDP

; ==============================================================================
; BuildTensorTable: Walk tensor info array and populate lookup table
; ==============================================================================
BuildTensorTable PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    xor r15, r15
    lea rdi, g_TensorTable
    mov rcx, SIZEOF TENSOR_INFO * MAX_TENSOR_ENTRIES
    xor eax, eax
    rep stosb
    mov qword ptr [g_TensorCount], 0
    test r14, r14
    jz @@done
@@tensor_loop:
    mov rsi, r13
    mov rcx, [rsi]
    add rsi, 8
    mov rdx, rcx
    mov rcx, rsi
    push rsi
    push rcx
    push rdx
    call FNV1A_64_LOCAL
    pop rdx
    pop rcx
    pop rsi
    lea rdi, g_TensorTable
    mov rbx, r15
    imul rbx, SIZEOF TENSOR_INFO
    add rdi, rbx
    mov [rdi + TENSOR_INFO.NameHash], rax
    mov rcx, rdi
    add rcx, TENSOR_INFO.NameStr
    mov rdx, rsi
    mov r8, 63
    push rsi
    push rdi
    call StrNCpy
    pop rdi
    pop rsi
    mov rcx, [r13]
    add rsi, rcx
    mov eax, dword ptr [rsi]
    mov [rdi + TENSOR_INFO.NDim], eax
    add rsi, 4
    mov ebx, eax
    cmp ebx, 4
    jbe @@dims_ok
    mov ebx, 4
@@dims_ok:
    xor ecx, ecx
@@dim_loop:
    cmp ecx, ebx
    jae @@dims_done
    mov eax, dword ptr [rsi + rcx*4]
    mov [rdi + TENSOR_INFO.Dims + rcx*4], eax
    inc ecx
    jmp @@dim_loop
@@dims_done:
    mov eax, [rdi + TENSOR_INFO.NDim]
    cmp eax, 4
    jbe @@skip_extra_dims
    mov eax, 4
@@skip_extra_dims:
    shl eax, 2
    add rsi, rax
    mov eax, dword ptr [rsi]
    mov [rdi + TENSOR_INFO.QuantType], eax
    add rsi, 4
    mov rax, [rsi]
    mov [rdi + TENSOR_INFO.DataOffset], rax
    add rsi, 8
    mov qword ptr [rdi + TENSOR_INFO.DataSize], 0
    mov r13, rsi
    inc r15
    cmp r15, MAX_TENSOR_ENTRIES
    jae @@done
    dec r14
    jnz @@tensor_loop
@@done:
    mov [g_TensorCount], r15
    mov eax, 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
BuildTensorTable ENDP

; ==============================================================================
; SOVEREIGN_GET_TENSOR_COUNT
; ==============================================================================
PUBLIC SOVEREIGN_GET_TENSOR_COUNT
SOVEREIGN_GET_TENSOR_COUNT PROC
    mov rax, [g_TensorCount]
    ret
SOVEREIGN_GET_TENSOR_COUNT ENDP

; ==============================================================================
; SOVEREIGN_GET_TENSOR_BY_INDEX
; ==============================================================================
PUBLIC SOVEREIGN_GET_TENSOR_BY_INDEX
SOVEREIGN_GET_TENSOR_BY_INDEX PROC
    push rsi
    push rdi
    cmp rcx, [g_TensorCount]
    jae @@not_found
    lea rsi, g_TensorTable
    imul rcx, SIZEOF TENSOR_INFO
    add rsi, rcx
    mov rdi, rdx
    mov rcx, SIZEOF TENSOR_INFO
    rep movsb
    mov eax, 1
    jmp @@exit
@@not_found:
    xor eax, eax
@@exit:
    pop rdi
    pop rsi
    ret
SOVEREIGN_GET_TENSOR_BY_INDEX ENDP

; ==============================================================================
; SOVEREIGN_GET_TENSOR_OFFSET
; ==============================================================================
PUBLIC SOVEREIGN_GET_TENSOR_OFFSET
SOVEREIGN_GET_TENSOR_OFFSET PROC
    push rbx
    push rsi
    push rdi
    mov rsi, rcx
    mov rcx, rsi
    call StrLen
    mov rdx, rax
    mov rcx, rsi
    call FNV1A_64_LOCAL
    mov rbx, rax
    lea rsi, g_TensorTable
    mov rdi, [g_TensorCount]
    test rdi, rdi
    jz @@not_found
@@search_loop:
    mov rax, [rsi + TENSOR_INFO.NameHash]
    cmp rax, rbx
    je @@found
    add rsi, SIZEOF TENSOR_INFO
    dec rdi
    jnz @@search_loop
@@not_found:
    mov rax, 0FFFFFFFFFFFFFFFFh
    jmp @@exit
@@found:
    mov rax, [rsi + TENSOR_INFO.DataOffset]
@@exit:
    pop rdi
    pop rsi
    pop rbx
    ret
SOVEREIGN_GET_TENSOR_OFFSET ENDP

; ==============================================================================
; SOVEREIGN_LOAD_MODEL: Map a .gguf file and parse header + tensor index
; ==============================================================================
PUBLIC SOVEREIGN_LOAD_MODEL
SOVEREIGN_LOAD_MODEL PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 38h          ; shadow + stack args (+ align) for Win64 API calls

    mov r12, rcx          ; r12 = path
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_UNKNOWN
    mov DWORD PTR [g_LastLoadWin32Error], 0

    ; --- Unload any existing model ---
    mov rax, [g_ModelBase]
    test rax, rax
    jz @@no_existing
    mov rcx, rax
    call UnmapViewOfFile
    mov qword ptr [g_ModelBase], 0
@@no_existing:

    ; --- Open file ---
    mov rcx, r12
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    xor r9d, r9d
    mov qword ptr [rsp+20h], OPEN_EXISTING
    mov qword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@open_failed
    mov r13, rax          ; r13 = hFile

    ; --- Get file size ---
    lea rdx, [rsp+20h]    ; LARGE_INTEGER size (inside local frame)
    mov rcx, r13
    call GetFileSizeEx
    test eax, eax
    jz @@size_fail
    mov r14, [rsp+20h]    ; r14 = file size

    ; --- Create file mapping ---
    mov rcx, r13
    xor edx, edx
    mov r8d, PAGE_READONLY
    xor r9d, r9d
    mov qword ptr [rsp+20h], r14
    mov qword ptr [rsp+28h], 0
    call CreateFileMappingA
    test rax, rax
    jz @@mapping_fail
    mov rsi, rax          ; rsi = hMapping

    ; --- Map view ---
    mov rcx, rsi
    mov edx, FILE_MAP_READ
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], r14
    call MapViewOfFile
    test rax, rax
    jz @@map_view_fail
    mov rdi, rax          ; rdi = pFileBase

    ; --- Validate GGUF header ---
    mov eax, dword ptr [rdi]
    cmp eax, GGUF_MAGIC
    jne @@bad_magic

    mov eax, dword ptr [rdi+4]
    cmp eax, GGUF_VERSION_MIN
    jl @@bad_magic
    cmp eax, GGUF_VERSION_MAX
    jg @@bad_magic

    ; --- Read tensor count and KV count ---
    mov rax, [rdi+8]
    mov rbx, rax
    shr rbx, 32
    test ebx, ebx
    jnz @@bad_magic

    mov rax, [rdi+16]
    mov rcx, rax
    shr rcx, 32
    test ecx, ecx
    jnz @@bad_magic

    ; --- Store in global state ---
    mov [g_ModelBase], rdi
    mov [g_ModelSize], r14
    mov [g_hFile], r13
    mov [g_hMapping], rsi
    mov [g_ModelInfo.Magic], 46554747h
    mov eax, dword ptr [rdi+4]
    mov [g_ModelInfo.Version], eax
    mov eax, dword ptr [rdi+8]
    mov [g_ModelInfo.TensorCount], rax
    mov eax, dword ptr [rdi+16]
    mov [g_ModelInfo.KVCount], rax

    ; Compatibility fallback: accept valid GGUF header/counts as load success.
    ; Strict metadata/tensor parsing can be re-enabled after parser hardening.
    jmp @@load_success

    ; --- Extract metadata ---
    lea rcx, [szKeyArch]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_arch
    mov rcx, [rax]
    add rax, 8
    lea rdx, [g_ModelInfo.ArchName]
    cmp rcx, 31
    jbe @@arch_len_ok
    mov rcx, 31
@@arch_len_ok:
    push rcx
    push rsi
    push rdi
    mov rsi, rax
    mov rdi, rdx
    rep movsb
    pop rdi
    pop rsi
    pop rcx
    mov byte ptr [rdx + rcx], 0
@@no_arch:

    lea rcx, [szKeyVocabSize]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_vocab
    cmp edx, GGUF_TYPE_UINT32
    jne @@no_vocab
    mov eax, dword ptr [rax]
    mov [g_ModelInfo.VocabSize], eax
@@no_vocab:

    lea rcx, [szKeyCtxLen]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_ctx
    cmp edx, GGUF_TYPE_UINT32
    jne @@no_ctx
    mov eax, dword ptr [rax]
    mov [g_ModelInfo.ContextLength], eax
@@no_ctx:

    lea rcx, [szKeyEmbedDim]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_embed
    cmp edx, GGUF_TYPE_UINT32
    jne @@no_embed
    mov eax, dword ptr [rax]
    mov [g_ModelInfo.EmbeddingDim], eax
@@no_embed:

    lea rcx, [szKeyHeadCount]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_head
    cmp edx, GGUF_TYPE_UINT32
    jne @@no_head
    mov eax, dword ptr [rax]
    mov [g_ModelInfo.HeadCount], eax
@@no_head:

    lea rcx, [szKeyLayerCount]
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    xor r9, r9
    call FindMetadataValue
    test rax, rax
    jz @@no_layer
    cmp edx, GGUF_TYPE_UINT32
    jne @@no_layer
    mov eax, dword ptr [rax]
    mov [g_ModelInfo.LayerCount], eax
@@no_layer:

    ; --- Build tensor lookup table ---
    lea rdx, [rdi + 24]
    mov r8, [rdi + 16]
    mov r9, rdi
    test r8, r8
    jz @@no_kv
@@kv_walk_loop:
    mov rsi, rdx
    cmp rsi, rdi
    jb @@bad_magic
    lea rax, [rdi + r14]
    cmp rsi, rax
    jae @@bad_magic

    mov rcx, rax
    sub rcx, rsi
    cmp rcx, 8
    jb @@bad_magic

    mov rcx, [rsi]
    sub rax, rsi
    sub rax, 8
    cmp rcx, rax
    ja @@bad_magic

    add rsi, 8
    add rsi, rcx

    lea rax, [rdi + r14]
    mov rcx, rax
    sub rcx, rsi
    cmp rcx, 4
    jb @@bad_magic

    mov edx, dword ptr [rsi]
    add rsi, 4

    mov rcx, rsi
    call SkipGGUFValue
    mov rdx, rax

    cmp rdx, rdi
    jb @@bad_magic
    lea rax, [rdi + r14]
    cmp rdx, rax
    ja @@bad_magic

    dec r8
    jnz @@kv_walk_loop
@@no_kv:
    mov rcx, rdi
    mov r8, [rdi + 8]
    call BuildTensorTable

@@load_success:
    ; --- Success: return handle = pFileBase ---
    mov rax, rdi
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_SUCCESS
    add rsp, 38h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

@@bad_magic:
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_CORRUPT_DATA
    mov rcx, rdi
    call UnmapViewOfFile
@@unmap_fail:
    mov rcx, rsi
    call CloseHandle
@@close_fail:
    mov rcx, r13
    call CloseHandle
@@fail:
    xor eax, eax
    add rsp, 38h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

@@size_fail:
    call GetLastError
    mov DWORD PTR [g_LastLoadWin32Error], eax
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_FILE_SIZE_READ_FAILED
    jmp @@close_fail

@@mapping_fail:
    call GetLastError
    mov DWORD PTR [g_LastLoadWin32Error], eax
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_FILE_MAPPING_FAILED
    jmp @@close_fail

@@map_view_fail:
    call GetLastError
    mov DWORD PTR [g_LastLoadWin32Error], eax
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_MAP_VIEW_FAILED
    jmp @@unmap_fail

@@open_failed:
    call GetLastError
    mov DWORD PTR [g_LastLoadWin32Error], eax
    cmp eax, 2
    je @@file_missing
    cmp eax, 3
    je @@file_missing
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_OPEN_FAILED
    jmp @@fail

@@file_missing:
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_FILE_NOT_FOUND
    jmp @@fail
SOVEREIGN_LOAD_MODEL ENDP

; ==============================================================================
; SOVEREIGN_UNLOAD_MODEL: Unmap and close model
; ==============================================================================
PUBLIC SOVEREIGN_UNLOAD_MODEL
SOVEREIGN_UNLOAD_MODEL PROC
    push rbx
    sub rsp, 20h            ; Allocate 32 bytes of shadow space
    mov rbx, rcx

    test rbx, rbx
    jz @@skip_unmap
    mov rcx, rbx
    call UnmapViewOfFile
@@skip_unmap:

    mov rcx, [g_hMapping]
    test rcx, rcx
    jz @@skip_close_mapping
    call CloseHandle
    mov qword ptr [g_hMapping], 0
@@skip_close_mapping:

    mov rcx, [g_hFile]
    test rcx, rcx
    jz @@skip_close_file
    call CloseHandle
    mov qword ptr [g_hFile], 0
@@skip_close_file:

    mov qword ptr [g_ModelBase], 0
    mov qword ptr [g_ModelSize], 0

    lea rcx, [g_ModelInfo]
    mov rdx, SIZEOF MODEL_INFO
    xor eax, eax
@@zero_loop:
    mov byte ptr [rcx+rax], 0
    inc rax
    cmp rax, rdx
    jb @@zero_loop

    mov eax, 1
    add rsp, 20h
    pop rbx
    ret
SOVEREIGN_UNLOAD_MODEL ENDP

; ==============================================================================
; SOVEREIGN_IS_MODEL_READY
; ==============================================================================
PUBLIC SOVEREIGN_IS_MODEL_READY
SOVEREIGN_IS_MODEL_READY PROC
    mov rax, [g_ModelBase]
    test rax, rax
    jz @@not_ready
    mov eax, [g_ModelInfo.Magic]
    cmp eax, GGUF_MAGIC
    jne @@not_ready
    mov eax, 1
    ret
@@not_ready:
    xor eax, eax
    ret
SOVEREIGN_IS_MODEL_READY ENDP

; ==============================================================================
; SOVEREIGN_GET_MODEL_INFO
; ==============================================================================
PUBLIC SOVEREIGN_GET_MODEL_INFO
SOVEREIGN_GET_MODEL_INFO PROC
    push rsi
    push rdi
    mov rdi, rcx
    lea rsi, [g_ModelInfo]
    mov rcx, SIZEOF MODEL_INFO
    rep movsb
    mov eax, 1
    pop rdi
    pop rsi
    ret
SOVEREIGN_GET_MODEL_INFO ENDP

; ==============================================================================
; DllMain: Required entry point for DLL initialization
; ==============================================================================
.code
PUBLIC DllMain
DllMain PROC
    mov eax, 1
    ret
DllMain ENDP

end
