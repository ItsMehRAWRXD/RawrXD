; =============================================================================
; vocab_loader.asm - GGUF Vocabulary Loader
; =============================================================================
; Loads and manages the tokenizer vocabulary from GGUF model files.
; Supports SentencePiece (SPM) and HuggingFace BPE tokenizer formats.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_VOCAB               EQU 128000
MAX_TOKEN_BYTES         EQU 256

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Vocabulary array
align 64
g_VocabArray            DQ MAX_VOCAB DUP(0)  ; Pointers to token strings
g_VocabScores           REAL4 MAX_VOCAB DUP(0.0)  ; Token scores
g_VocabSize             DQ 0

; Token string pool
align 64
g_TokenPool             DB 32 * 1024 * 1024 DUP(0)  ; 32MB pool
g_TokenPoolOffset       DQ 0

; Special token IDs
align 8
g_SpecialBOS            DQ 1
g_SpecialEOS            DQ 2
g_SpecialUNK            DQ 0
g_SpecialPAD            DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Vocab_LoadFromGGUF - Load vocabulary from GGUF metadata
;
; Parameters:
;   RCX = QWORD metadata_ptr  - Pointer to GGUF metadata section
;   RDX = QWORD kv_count      - Number of KV pairs
;   R8  = QWORD mmap_base     - Memory-mapped file base
;
; Returns: RAX = vocab size, or 0 on error
; =============================================================================
Vocab_LoadFromGGUF PROC FRAME
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

    mov rsi, rcx                    ; metadata_ptr
    mov r12, rdx                    ; kv_count

    ; Reset vocab
    mov QWORD PTR [g_VocabSize], 0
    mov QWORD PTR [g_TokenPoolOffset], 0

    xor r13, r13

@@kv_loop:
    cmp r13, r12
    jge @@done

    ; Read key
    mov r14d, DWORD PTR [rsi]
    lea r15, [rsi + 4]
    lea rsi, [rsi + 4 + r14]

    ; Read value type
    mov r8d, DWORD PTR [rsi]
    add rsi, 4

    ; Check for tokenizer.ggml.tokens
    mov rcx, r15
    lea rdx, szKeyTokens
    call Vocab_StrCmp
    test rax, rax
    jnz @@check_scores

    ; Found token list - it's an array of strings
    mov r14d, DWORD PTR [rsi]      ; array length
    add rsi, 4
    mov QWORD PTR [g_VocabSize], r14

    xor r9, r9

@@token_loop:
    cmp r9, r14
    jge @@next_kv
    cmp r9, MAX_VOCAB
    jge @@next_kv

    ; Read score
    movss xmm0, DWORD PTR [rsi]
    movss DWORD PTR [g_VocabScores + r9*4], xmm0
    add rsi, 4

    ; Read string length
    mov r10d, DWORD PTR [rsi]
    add rsi, 4

    ; Copy to pool
    mov rdi, QWORD PTR [g_TokenPoolOffset]
    lea r11, g_TokenPool
    add r11, rdi

    mov rcx, rsi
    mov rdx, r11
    mov r8, r10
    call Vocab_MemCopy

    mov BYTE PTR [r11 + r10], 0

    ; Store pointer
    mov QWORD PTR [g_VocabArray + r9*8], r11

    add rdi, r10
    add rdi, 1
    mov QWORD PTR [g_TokenPoolOffset], rdi

    add rsi, r10
    inc r9
    jmp @@token_loop

@@check_scores:
    ; Check for tokenizer.ggml.scores
    mov rcx, r15
    lea rdx, szKeyScores
    call Vocab_StrCmp
    test rax, rax
    jnz @@check_bos

    ; Scores array
    mov r14d, DWORD PTR [rsi]
    add rsi, 4
    xor r9, r9

@@score_loop:
    cmp r9, r14
    jge @@next_kv
    cmp r9, MAX_VOCAB
    jge @@next_kv
    movss xmm0, DWORD PTR [rsi]
    movss DWORD PTR [g_VocabScores + r9*4], xmm0
    add rsi, 4
    inc r9
    jmp @@score_loop

@@check_bos:
    mov rcx, r15
    lea rdx, szKeyBOS
    call Vocab_StrCmp
    test rax, rax
    jnz @@check_eos
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_SpecialBOS], rax
    add rsi, 8
    jmp @@next_kv

@@check_eos:
    mov rcx, r15
    lea rdx, szKeyEOS
    call Vocab_StrCmp
    test rax, rax
    jnz @@check_unk
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_SpecialEOS], rax
    add rsi, 8
    jmp @@next_kv

@@check_unk:
    mov rcx, r15
    lea rdx, szKeyUNK
    call Vocab_StrCmp
    test rax, rax
    jnz @@skip_value
    mov rax, QWORD PTR [rsi]
    mov QWORD PTR [g_SpecialUNK], rax
    add rsi, 8
    jmp @@next_kv

@@skip_value:
    ; Skip value
    cmp r8d, 8
    je @@skip_8
    cmp r8d, 6
    je @@skip_4
    cmp r8d, 4
    je @@skip_4
    add rsi, 8
    jmp @@next_kv
@@skip_8:
    add rsi, 8
    jmp @@next_kv
@@skip_4:
    add rsi, 4

@@next_kv:
    inc r13
    jmp @@kv_loop

@@done:
    mov rax, QWORD PTR [g_VocabSize]
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

Vocab_LoadFromGGUF ENDP

; =============================================================================
; Vocab_Lookup - Find token ID by string
;
; Parameters:
;   RCX = char* token_str
;
; Returns: RAX = token ID, or UNK if not found
; =============================================================================
Vocab_Lookup PROC FRAME
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@not_found

    mov rsi, rcx
    mov r12, QWORD PTR [g_VocabSize]

    xor rdi, rdi

@@loop:
    cmp rdi, r12
    jge @@not_found

    mov rdx, QWORD PTR [g_VocabArray + rdi*8]
    test rdx, rdx
    jz @@next

    mov rcx, rsi
    call Vocab_StrCmp
    test rax, rax
    jz @@found

@@next:
    inc rdi
    jmp @@loop

@@found:
    mov rax, rdi
    jmp @@exit

@@not_found:
    mov rax, QWORD PTR [g_SpecialUNK]

@@exit:
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Vocab_Lookup ENDP

; =============================================================================
; Vocab_Decode - Decode token ID to string
;
; Parameters:
;   RCX = QWORD token_id
;
; Returns: RAX = pointer to token string, or NULL
; =============================================================================
Vocab_Decode PROC FRAME
    .endprolog
    cmp rcx, QWORD PTR [g_VocabSize]
    jae @@error
    mov rax, QWORD PTR [g_VocabArray + rcx*8]
    test rax, rax
    jz @@error
    ret
@@error:
    xor rax, rax
    ret
Vocab_Decode ENDP

; =============================================================================
; Vocab_GetSpecial - Get special token ID
;
; Parameters:
;   RCX = QWORD type  (0=BOS, 1=EOS, 2=UNK, 3=PAD)
;
; Returns: RAX = token ID
; =============================================================================
Vocab_GetSpecial PROC FRAME
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
@@bos: mov rax, QWORD PTR [g_SpecialBOS]; ret
@@eos: mov rax, QWORD PTR [g_SpecialEOS]; ret
@@unk: mov rax, QWORD PTR [g_SpecialUNK]; ret
@@pad: mov rax, QWORD PTR [g_SpecialPAD]; ret
Vocab_GetSpecial ENDP

; =============================================================================
; Helpers
; =============================================================================
Vocab_StrCmp PROC PRIVATE FRAME
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
Vocab_StrCmp ENDP

Vocab_MemCopy PROC PRIVATE FRAME
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
Vocab_MemCopy ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 8
szKeyTokens         DB 'tokenizer.ggml.tokens', 0
szKeyScores         DB 'tokenizer.ggml.scores', 0
szKeyBOS            DB 'tokenizer.ggml.bos_token_id', 0
szKeyEOS            DB 'tokenizer.ggml.eos_token_id', 0
szKeyUNK            DB 'tokenizer.ggml.unknown_token_id', 0

END
