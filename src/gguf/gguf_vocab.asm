; =============================================================================
; gguf_vocab.asm - GGUF Vocabulary / Tokenizer Extractor
; =============================================================================
; Extracts the tokenizer vocabulary from a GGUF file.
; Supports:
;   - SentencePiece BPE vocab (score + token strings)
;   - Special token IDs (BOS, EOS, UNK, PAD)
;   - Score-based token ranking
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_VOCAB_ENTRIES       EQU 128000
MAX_TOKEN_STRING_LEN    EQU 256

; GGUF tokenizer types
GGUF_TOKENIZER_BPE      EQU 1
GGUF_TOKENIZER_SPM      EQU 2

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Vocabulary table
align 64
g_VocabTable            DB MAX_VOCAB_ENTRIES * 16 DUP(0)  ; 16 bytes per entry

; Vocab entry structure (16 bytes):
;   +0: QWORD token_id
;   +8: QWORD score (as float, or 0 if not scored)
; String data stored separately

; Token string data pool
align 64
g_VocabStrings          DB 16 * 1024 * 1024 DUP(0)  ; 16MB pool
g_VocabStringsOffset    DQ 0

; Special token IDs
align 8
g_BOS_ID                DQ 1
g_EOS_ID                DQ 2
g_UNK_ID                DQ 0
g_PAD_ID                DQ 0

; Vocab metadata
align 8
g_VocabSize             DQ 0
g_TokenizerType         DQ GGUF_TOKENIZER_BPE

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; GGUF_LoadVocab - Extract vocabulary from GGUF metadata
;
; Parameters:
;   RCX = QWORD metadata_ptr  - Pointer to metadata section
;   RDX = QWORD kv_count      - Number of KV pairs
;   R8  = QWORD mmap_base     - Memory-mapped file base
;
; Returns: RAX = vocab size, or 0 on error
; =============================================================================
GGUF_LoadVocab PROC FRAME
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
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; metadata_ptr
    mov r12, rdx                    ; kv_count
    mov QWORD PTR [rbp - 8], r8    ; mmap_base

    ; Reset vocab state
    mov QWORD PTR [g_VocabSize], 0
    mov QWORD PTR [g_VocabStringsOffset], 0

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

    ; Check for tokenizer.ggml.* keys
    mov rcx, r15
    lea rdx, szKeyTokenizerBOS
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_bos

    mov rcx, r15
    lea rdx, szKeyTokenizerEOS
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_eos

    mov rcx, r15
    lea rdx, szKeyTokenizerUNK
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_unk

    mov rcx, r15
    lea rdx, szKeyTokenizerPAD
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_pad

    mov rcx, r15
    lea rdx, szKeyTokenizerList
    call RawrXD_StrCmp
    test rax, rax
    jz @@match_token_list

    jmp @@skip_value

@@match_bos:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_BOS_ID], rax
    add rsi, 8
    jmp @@next_pair

@@match_eos:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_EOS_ID], rax
    add rsi, 8
    jmp @@next_pair

@@match_unk:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_UNK_ID], rax
    add rsi, 8
    jmp @@next_pair

@@match_pad:
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_PAD_ID], rax
    add rsi, 8
    jmp @@next_pair

@@match_token_list:
    ; Token list is an array of strings
    ; Each entry: [score: float32] [text: string]
    mov r14d, DWORD PTR [rsi]      ; array length
    add rsi, 4
    mov QWORD PTR [g_VocabSize], r14

    xor r9, r9                      ; token index

@@token_loop:
    cmp r9, r14
    jge @@next_pair
    cmp r9, MAX_VOCAB_ENTRIES
    jge @@next_pair

    ; Read score (float32)
    movss xmm0, DWORD PTR [rsi]
    add rsi, 4

    ; Read token text length
    mov r10d, DWORD PTR [rsi]
    add rsi, 4

    ; Copy token text to string pool
    mov rdi, QWORD PTR [g_VocabStringsOffset]
    lea r11, g_VocabStrings
    add r11, rdi

    ; Limit string length
    mov r10d, r10d
    cmp r10, MAX_TOKEN_STRING_LEN
    jbe @@strlen_ok
    mov r10, MAX_TOKEN_STRING_LEN
@@strlen_ok:

    ; Copy string
    mov rcx, rsi
    mov rdx, r11
    mov r8, r10
    call RawrXD_MemCopyBounded

    ; Null-terminate
    mov BYTE PTR [r11 + r10], 0

    ; Update string pool offset
    add rdi, r10
    add rdi, 1
    mov QWORD PTR [g_VocabStringsOffset], rdi

    ; Store in vocab table
    mov rax, r9
    shl rax, 4                      ; * 16
    lea rdi, g_VocabTable
    add rdi, rax
    mov QWORD PTR [rdi], r9         ; token_id
    movss DWORD PTR [rdi + 8], xmm0 ; score

    ; Advance past token text
    add rsi, r10
    inc r9
    jmp @@token_loop

@@skip_value:
    ; Skip value (same as gguf_metadata.asm logic)
    cmp r8d, 4
    jle @@skip_small
    cmp r8d, 6
    je @@skip_4
    cmp r8d, 8
    je @@skip_string
    cmp r8d, 9
    je @@skip_array
    add rsi, 8
    jmp @@next_pair
@@skip_small:
    add rsi, 1
    jmp @@next_pair
@@skip_4:
    add rsi, 4
    jmp @@next_pair
@@skip_string:
    mov eax, DWORD PTR [rsi]
    add rsi, 4
    add rsi, rax
    jmp @@next_pair
@@skip_array:
    mov eax, DWORD PTR [rsi]
    add rsi, 4
    add rsi, 8

@@next_pair:
    inc r13
    jmp @@pair_loop

@@done:
    mov rax, QWORD PTR [g_VocabSize]
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GGUF_LoadVocab ENDP

; =============================================================================
; GGUF_GetSpecialToken - Get a special token ID
;
; Parameters:
;   RCX = QWORD token_type  - 0=BOS, 1=EOS, 2=UNK, 3=PAD
;
; Returns: RAX = token ID
; =============================================================================
GGUF_GetSpecialToken PROC FRAME
    .endprolog
    cmp rcx, 0
    je @@bos
    cmp rcx, 1
    je @@eos
    cmp rcx, 2
    je @@unk
    cmp rcx, 3
    je @@pad
    xor rax, rax
    ret
@@bos:  mov rax, QWORD PTR [g_BOS_ID]; ret
@@eos:  mov rax, QWORD PTR [g_EOS_ID]; ret
@@unk:  mov rax, QWORD PTR [g_UNK_ID]; ret
@@pad:  mov rax, QWORD PTR [g_PAD_ID]; ret
GGUF_GetSpecialToken ENDP

; =============================================================================
; RawrXD_MemCopyBounded - Bounded memory copy
; =============================================================================
RawrXD_MemCopyBounded PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    test r8, r8
    jz @@exit

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

RawrXD_MemCopyBounded ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 8
szKeyTokenizerBOS      DB 'tokenizer.ggml.bos_token_id', 0
szKeyTokenizerEOS      DB 'tokenizer.ggml.eos_token_id', 0
szKeyTokenizerUNK      DB 'tokenizer.ggml.unknown_token_id', 0
szKeyTokenizerPAD      DB 'tokenizer.ggml.padding_token_id', 0
szKeyTokenizerList     DB 'tokenizer.ggml.tokens', 0

END
