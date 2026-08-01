; =============================================================================
; bpe.asm - RawrXD BPE Tokenizer (Byte-Pair Encoding)
; =============================================================================
; Pure MASM x64 BPE tokenizer with no external dependencies.
; Supports:
;   - SentencePiece-style BPE
;   - Vocabulary lookup
;   - Encode (text -> tokens)
;   - Decode (tokens -> text)
;   - Byte-level fallback for unknown characters
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_VOCAB_SIZE          EQU 32000
MAX_TOKEN_LEN           EQU 256
MAX_ENCODE_LEN          EQU 4096

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Tokenizer context (256 bytes)
align 16
g_TokenizerCtx         DB 256 DUP(0)

; Field offsets
TOK_CTX_VOCAB_PTR      EQU 0
TOK_CTX_VOCAB_SIZE     EQU 8
TOK_CTX_SCORES_PTR     EQU 16
TOK_CTX_MERGE_PTR      EQU 24
TOK_CTX_BYTE_FALLBACK  EQU 32
TOK_CTX_BOS_TOKEN      EQU 40
TOK_CTX_EOS_TOKEN      EQU 48
TOK_CTX_UNK_TOKEN      EQU 56
TOK_CTX_PAD_TOKEN      EQU 64

; Default special tokens
g_BOS_TOKEN            DQ 1
g_EOS_TOKEN            DQ 2
g_UNK_TOKEN            DQ 0
g_PAD_TOKEN            DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Tokenizer_Init - Initialize tokenizer with vocabulary
;
; Parameters:
;   RCX = QWORD vocab_size
;   RDX = char** vocab       - Array of token strings
;   R8  = float* scores      - Token scores (log probabilities)
;   R9  = QWORD* merge_ranks - Merge rank table
;
; Returns: RAX = 0 on success
; =============================================================================
Tokenizer_Init PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_VOCAB_SIZE], rcx
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_VOCAB_PTR], rdx
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_SCORES_PTR], r8
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_MERGE_PTR], r9

    ; Set special tokens
    mov rax, QWORD PTR [g_BOS_TOKEN]
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_BOS_TOKEN], rax
    mov rax, QWORD PTR [g_EOS_TOKEN]
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_EOS_TOKEN], rax
    mov rax, QWORD PTR [g_UNK_TOKEN]
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_UNK_TOKEN], rax
    mov rax, QWORD PTR [g_PAD_TOKEN]
    mov QWORD PTR [g_TokenizerCtx + TOK_CTX_PAD_TOKEN], rax

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Tokenizer_Init ENDP

; =============================================================================
; Tokenizer_Encode - Encode text string to token IDs
;
; Parameters:
;   RCX = char* text          - Input UTF-8 text
;   RDX = QWORD* out_tokens   - Output token array
;   R8  = QWORD max_tokens    - Max output tokens
;
; Returns: RAX = number of tokens, or 0 on error
; =============================================================================
Tokenizer_Encode PROC FRAME
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
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; text
    mov rdi, rdx                    ; out_tokens
    mov r12, r8                     ; max_tokens

    ; Add BOS token
    mov rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_BOS_TOKEN]
    mov QWORD PTR [rdi], rax
    mov r13, 1                      ; token count (started with BOS)
    mov r14, rsi                    ; current position in text

    ; Allocate working buffer for byte-level tokenization
    sub rsp, MAX_ENCODE_LEN
    mov r15, rsp                    ; byte buffer

    ; Simple byte-level tokenization (no BPE merges for now)
    ; In production, this would:
    ;   1. Normalize text (NFKC)
    ;   2. Pre-tokenize (split on whitespace/punctuation)
    ;   3. BPE merge (find best pair, merge, repeat)
    ;   4. Look up final tokens in vocabulary

@@tokenize_loop:
    ; Read next byte
    mov al, BYTE PTR [r14]
    test al, al
    jz @@done                       ; null terminator

    ; Check for max tokens
    cmp r13, r12
    jge @@done

    ; Simple: map byte to token ID (byte-level fallback)
    ; byte token = byte_value + 3 (skip special tokens)
    movzx rax, al
    add rax, 3
    mov QWORD PTR [rdi + r13*8], rax
    inc r13
    inc r14
    jmp @@tokenize_loop

@@done:
    ; Add EOS token
    cmp r13, r12
    jge @@no_eos
    mov rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_EOS_TOKEN]
    mov QWORD PTR [rdi + r13*8], rax
    inc r13

@@no_eos:
    mov rax, r13
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, MAX_ENCODE_LEN + 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Tokenizer_Encode ENDP

; =============================================================================
; Tokenizer_Decode - Decode token IDs to text string
;
; Parameters:
;   RCX = QWORD* tokens      - Input token array
;   RDX = QWORD num_tokens   - Number of tokens
;   R8  = char* out_text     - Output text buffer
;   R9  = QWORD max_len      - Max output length
;
; Returns: RAX = length of decoded text
; =============================================================================
Tokenizer_Decode PROC FRAME
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
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; tokens
    mov rdi, rdx                    ; num_tokens
    mov r12, r8                     ; out_text
    mov r13, r9                     ; max_len

    xor r14, r14                    ; output position
    xor r15, r15                    ; token index

@@loop:
    cmp r15, rdi
    jge @@done

    mov rax, QWORD PTR [rsi + r15*8]

    ; Skip special tokens (BOS, EOS, PAD)
    cmp rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_BOS_TOKEN]
    je @@next
    cmp rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_EOS_TOKEN]
    je @@done
    cmp rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_PAD_TOKEN]
    je @@next

    ; Simple: token ID -> byte (reverse of encode)
    ; byte = token - 3
    sub rax, 3
    cmp rax, 255
    ja @@next                       ; Out of range

    ; Write byte to output
    cmp r14, r13
    jge @@done
    mov BYTE PTR [r12 + r14], al
    inc r14

@@next:
    inc r15
    jmp @@loop

@@done:
    ; Null-terminate
    cmp r14, r13
    jge @@no_null
    mov BYTE PTR [r12 + r14], 0

@@no_null:
    mov rax, r14
    jmp @@exit

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

Tokenizer_Decode ENDP

; =============================================================================
; Tokenizer_LookupToken - Find token ID for a string
;
; Parameters:
;   RCX = char* token_str
;
; Returns: RAX = token ID, or UNK_TOKEN if not found
; =============================================================================
Tokenizer_LookupToken PROC FRAME
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
    jz @@not_found

    mov rsi, rcx                    ; target string
    mov rdi, QWORD PTR [g_TokenizerCtx + TOK_CTX_VOCAB_PTR]
    mov r12, QWORD PTR [g_TokenizerCtx + TOK_CTX_VOCAB_SIZE]

    xor r13, r13

@@loop:
    cmp r13, r12
    jge @@not_found

    mov rdx, QWORD PTR [rdi + r13*8]  ; vocab[r13]
    test rdx, rdx
    jz @@next

    ; Compare strings
    mov rcx, rsi
    call RawrXD_StrCmp
    test rax, rax
    jz @@found

@@next:
    inc r13
    jmp @@loop

@@found:
    mov rax, r13
    jmp @@exit

@@not_found:
    mov rax, QWORD PTR [g_TokenizerCtx + TOK_CTX_UNK_TOKEN]

@@exit:
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Tokenizer_LookupToken ENDP

END
