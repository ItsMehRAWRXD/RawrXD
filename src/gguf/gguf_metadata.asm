; =============================================================================
; gguf_metadata.asm - GGUF Metadata KV Parser
; =============================================================================
; Parses the metadata key-value pairs in a GGUF file header.
; Extracts model architecture parameters needed for inference:
;   - context_length
;   - embedding_length
;   - block_count
;   - head_count
;   - head_count_kv
;   - layer_norm_rms_epsilon
;   - vocab_size
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
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

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Parsed model parameters
align 8
g_ModelParams          DB 128 DUP(0)

; Parameter offsets
PARAM_N_LAYERS         EQU 0   ; QWORD
PARAM_N_EMBED          EQU 8   ; QWORD
PARAM_N_HEADS          EQU 16  ; QWORD
PARAM_N_HEADS_KV       EQU 24  ; QWORD
PARAM_N_CTX_LEN        EQU 32  ; QWORD
PARAM_N_VOCAB          EQU 40  ; QWORD
PARAM_RMS_EPS          EQU 48  ; REAL4
PARAM_ARCH             EQU 52  ; DWORD

; Key strings to match
align 8
szKeyBlockCount        DB 'block_count', 0
szKeyEmbedLength       DB 'embedding_length', 0
szKeyHeadCount         DB 'head_count', 0
szKeyHeadCountKV       DB 'head_count_kv', 0
szKeyCtxLength         DB 'context_length', 0
szKeyVocabSize         DB 'vocab_size', 0
szKeyRMSEps            DB 'layer_norm_rms_epsilon', 0
szKeyArch              DB 'general.architecture', 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; GGUF_ParseMetadata - Parse GGUF metadata KV pairs
;
; Parameters:
;   RCX = QWORD metadata_ptr  - Pointer to first KV pair
;   RDX = QWORD kv_count      - Number of KV pairs
;
; Returns: RAX = 0 on success
; =============================================================================
GGUF_ParseMetadata PROC FRAME
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
    jz @@done

    mov rsi, rcx                    ; metadata_ptr
    mov r12, rdx                    ; kv_count

    ; Set defaults
    mov QWORD PTR [g_ModelParams + PARAM_N_LAYERS], 32
    mov QWORD PTR [g_ModelParams + PARAM_N_EMBED], 4096
    mov QWORD PTR [g_ModelParams + PARAM_N_HEADS], 32
    mov QWORD PTR [g_ModelParams + PARAM_N_HEADS_KV], 8
    mov QWORD PTR [g_ModelParams + PARAM_N_CTX_LEN], 4096
    mov QWORD PTR [g_ModelParams + PARAM_N_VOCAB], 32000
    movss xmm0, DWORD PTR [g_DefEps]
    movss DWORD PTR [g_ModelParams + PARAM_RMS_EPS], xmm0
    mov DWORD PTR [g_ModelParams + PARAM_ARCH], 0

    xor r13, r13                    ; pair index

@@pair_loop:
    cmp r13, r12
    jge @@done

    ; Read key length
    mov r14d, DWORD PTR [rsi]
    lea r15, [rsi + 4]             ; r15 = key string

    ; Skip key
    lea rsi, [rsi + 4 + r14]

    ; Read value type
    mov r8d, DWORD PTR [rsi]
    add rsi, 4

    ; Match key and extract value
    mov rcx, r15
    lea rdx, szKeyBlockCount
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_block_count

    mov rcx, r15
    lea rdx, szKeyEmbedLength
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_embed_length

    mov rcx, r15
    lea rdx, szKeyHeadCount
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_head_count

    mov rcx, r15
    lea rdx, szKeyHeadCountKV
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_head_count_kv

    mov rcx, r15
    lea rdx, szKeyCtxLength
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_ctx_length

    mov rcx, r15
    lea rdx, szKeyVocabSize
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_vocab_size

    mov rcx, r15
    lea rdx, szKeyRMSEps
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_rms_eps

    jmp @@skip_value

@@match_block_count:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_LAYERS], rax
    add rsi, 8
    jmp @@next_pair

@@match_embed_length:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_EMBED], rax
    add rsi, 8
    jmp @@next_pair

@@match_head_count:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_HEADS], rax
    add rsi, 8
    jmp @@next_pair

@@match_head_count_kv:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_HEADS_KV], rax
    add rsi, 8
    jmp @@next_pair

@@match_ctx_length:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_CTX_LEN], rax
    add rsi, 8
    jmp @@next_pair

@@match_vocab_size:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_ModelParams + PARAM_N_VOCAB], rax
    add rsi, 8
    jmp @@next_pair

@@match_rms_eps:
    movss xmm0, DWORD PTR [rsi]
    movss DWORD PTR [g_ModelParams + PARAM_RMS_EPS], xmm0
    add rsi, 4
    jmp @@next_pair

@@skip_value:
    ; Skip value based on type
    cmp r8d, GGUF_VALUE_UINT8
    je @@skip_1
    cmp r8d, GGUF_VALUE_INT8
    je @@skip_1
    cmp r8d, GGUF_VALUE_BOOL
    je @@skip_1
    cmp r8d, GGUF_VALUE_UINT16
    je @@skip_2
    cmp r8d, GGUF_VALUE_INT16
    je @@skip_2
    cmp r8d, GGUF_VALUE_FLOAT32
    je @@skip_4
    cmp r8d, GGUF_VALUE_INT32
    je @@skip_4
    cmp r8d, GGUF_VALUE_UINT32
    je @@skip_4
    cmp r8d, GGUF_VALUE_FLOAT64
    je @@skip_8
    cmp r8d, GGUF_VALUE_UINT64
    je @@skip_8
    cmp r8d, GGUF_VALUE_INT64
    je @@skip_8
    cmp r8d, GGUF_VALUE_STRING
    je @@skip_string
    cmp r8d, GGUF_VALUE_ARRAY
    je @@skip_array
    jmp @@next_pair

@@skip_1:
    add rsi, 1
    jmp @@next_pair
@@skip_2:
    add rsi, 2
    jmp @@next_pair
@@skip_4:
    add rsi, 4
    jmp @@next_pair
@@skip_8:
    add rsi, 8
    jmp @@next_pair
@@skip_string:
    mov eax, DWORD PTR [rsi]
    add rsi, 4
    add rsi, rax
    jmp @@next_pair
@@skip_array:
    mov eax, DWORD PTR [rsi]
    add rsi, 4
    ; Skip array elements (simplified)
    add rsi, 8

@@next_pair:
    inc r13
    jmp @@pair_loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

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

GGUF_ParseMetadata ENDP

; =============================================================================
; GGUF_GetParam - Get a parsed model parameter
;
; Parameters:
;   RCX = QWORD param_offset  - PARAM_* offset
;   RDX = QWORD* out_value    - Output buffer
;
; Returns: RAX = 0 on success
; =============================================================================
GGUF_GetParam PROC FRAME
    .endprolog
    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    cmp rcx, 128
    jae @@error

    mov rax, QWORD PTR [g_ModelParams + rcx]
    mov QWORD PTR [rdx], rax
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    ret

GGUF_GetParam ENDP

; =============================================================================
; RawrXD_StrCmp - String comparison
; =============================================================================
RawrXD_StrCmp PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@not_equal
    test rdx, rdx
    jz @@not_equal

    xor eax, eax
@@loop:
    mov al, BYTE PTR [rcx]
    mov bl, BYTE PTR [rdx]
    cmp al, bl
    jne @@not_equal
    test al, al
    jz @@equal
    inc rcx
    inc rdx
    jmp @@loop

@@equal:
    xor eax, eax
    ret

@@not_equal:
    mov eax, 1
    ret

RawrXD_StrCmp ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_DefEps            REAL4 1.0e-5

END
