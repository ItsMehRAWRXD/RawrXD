; =============================================================================
; model_context.asm - RawrXD Model Context & Generation Runtime
; =============================================================================
; Manages the complete model execution context:
;   - Model weights (from GGUF)
;   - Inference state (position, KV cache, etc.)
;   - Generation loop (prefill + decode)
;   - Logits processing
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_MODEL_CTX_SIZE     EQU 65536   ; 64KB model context

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Model context structure
align 64
g_ModelCtx             DB MAX_MODEL_CTX_SIZE DUP(0)

; Context field offsets
MODEL_CTX_GGUF_PTR     EQU 0    ; QWORD - GGUF context pointer
MODEL_CTX_N_LAYERS     EQU 8    ; QWORD
MODEL_CTX_N_EMBED      EQU 16   ; QWORD
MODEL_CTX_N_HEADS      EQU 24   ; QWORD
MODEL_CTX_N_HEADS_KV   EQU 32   ; QWORD
MODEL_CTX_HEAD_DIM     EQU 40   ; QWORD
MODEL_CTX_N_CTX_LEN    EQU 48   ; QWORD
MODEL_CTX_VOCAB_SIZE   EQU 56   ; QWORD
MODEL_CTX_RMS_EPS      EQU 64   ; REAL4
MODEL_CTX_CUR_POS      EQU 72   ; QWORD - current position
MODEL_CTX_EMBED_BUF    EQU 80   ; QWORD - embedding buffer
MODEL_CTX_HIDDEN_BUF   EQU 88   ; QWORD - hidden state buffer
MODEL_CTX_LOGITS_BUF   EQU 96   ; QWORD - logits buffer
MODEL_CTX_KV_CACHE     EQU 104  ; QWORD - KV cache pointer
MODEL_CTX_WEIGHT_PTRS  EQU 112  ; QWORD - weight table pointer
MODEL_CTX_LOADED       EQU 120  ; BYTE  - model loaded flag

; Weight index offsets (each is QWORD pointer)
WEIGHT_TOKEN_EMB       EQU 0
WEIGHT_OUTPUT_NORM     EQU 8
WEIGHT_OUTPUT          EQU 16
WEIGHT_ATTN_NORM       EQU 24   ; + layer * 48
WEIGHT_ATTN_Q          EQU 32
WEIGHT_ATTN_K          EQU 40
WEIGHT_ATTN_V          EQU 48
WEIGHT_ATTN_OUT        EQU 56
WEIGHT_FFN_NORM        EQU 64
WEIGHT_FFN_GATE        EQU 72
WEIGHT_FFN_UP          EQU 80
WEIGHT_FFN_DOWN        EQU 88
; Per-layer stride: 96 bytes

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_ModelContext_Init - Initialize model context
;
; Parameters:
;   RCX = QWORD gguf_ctx  - GGUF context pointer
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_ModelContext_Init PROC FRAME
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

    mov rsi, rcx                    ; gguf_ctx

    ; Zero context
    lea rdi, g_ModelCtx
    mov rcx, MAX_MODEL_CTX_SIZE
    xor eax, eax
    rep stosb

    ; Store GGUF pointer
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_GGUF_PTR], rsi

    ; Read model parameters from GGUF metadata
    ; (In production, call GGUF_ParseMetadata)
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_N_LAYERS], 32
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_N_EMBED], 4096
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_N_HEADS], 32
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_N_HEADS_KV], 8
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_HEAD_DIM], 128
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_N_CTX_LEN], 4096
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_VOCAB_SIZE], 32000
    movss xmm0, DWORD PTR [g_DefEps]
    movss DWORD PTR [g_ModelCtx + MODEL_CTX_RMS_EPS], xmm0

    ; Allocate working buffers
    mov r12, QWORD PTR [g_ModelCtx + MODEL_CTX_N_EMBED]
    shl r12, 2                      ; * 4 bytes

    mov rcx, r12
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_EMBED_BUF], rax

    mov rcx, r12
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_embed
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_HIDDEN_BUF], rax

    ; Allocate logits buffer
    mov rax, QWORD PTR [g_ModelCtx + MODEL_CTX_VOCAB_SIZE]
    shl rax, 2
    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_hidden
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_LOGITS_BUF], rax

    ; Initialize KV cache
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_CTX_LEN]
    mov rdx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_LAYERS]
    mov r8, QWORD PTR [g_ModelCtx + MODEL_CTX_N_HEADS_KV]
    mov r9, QWORD PTR [g_ModelCtx + MODEL_CTX_HEAD_DIM]
    sub rsp, 32
    mov DWORD PTR [rsp + 32], 0     ; F32
    call RawrXD_KVCacheCreate
    add rsp, 32
    test rax, rax
    jnz @@free_logits
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_KV_CACHE], rax

    ; Initialize attention workspace
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_CTX_LEN]
    mov rdx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_HEADS]
    mov r8, QWORD PTR [g_ModelCtx + MODEL_CTX_HEAD_DIM]
    call RawrXD_AttentionInit
    test rax, rax
    jnz @@free_kv

    ; Initialize SwiGLU workspace
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_EMBED]
    mov rdx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_EMBED]
    imul rdx, 8                     ; ffn_dim = 8/3 * hidden_dim (approx)
    shr rdx, 2
    call RawrXD_SwiGLU_Init
    test rax, rax
    jnz @@free_kv

    ; Initialize RoPE tables
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_HEAD_DIM]
    mov rdx, QWORD PTR [g_ModelCtx + MODEL_CTX_N_CTX_LEN]
    movss xmm1, DWORD PTR [g_RopeTheta]
    call RawrXD_RoPE_Init
    test rax, rax
    jnz @@free_kv

    mov BYTE PTR [g_ModelCtx + MODEL_CTX_LOADED], 1
    xor rax, rax
    jmp @@exit

@@free_kv:
    ; Free KV cache
@@free_logits:
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_LOGITS_BUF]
    call RawrXD_AlignedFree
@@free_hidden:
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_HIDDEN_BUF]
    call RawrXD_AlignedFree
@@free_embed:
    mov rcx, QWORD PTR [g_ModelCtx + MODEL_CTX_EMBED_BUF]
    call RawrXD_AlignedFree
@@error:
    mov rax, 1

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

RawrXD_ModelContext_Init ENDP

; =============================================================================
; RawrXD_Logits_Process - Process logits for sampling
;
; Parameters:
;   RCX = float* logits     - Raw logits
;   RDX = QWORD vocab_size  - Vocabulary size
;   R8  = float temperature - Temperature
;   R9  = QWORD top_k       - Top-K value
;   [RBP+48] = float top_p  - Top-P value
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_Logits_Process PROC FRAME
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

    mov rsi, rcx                    ; logits
    mov rdi, rdx                    ; vocab_size

    ; 1. Apply temperature
    movss xmm0, r8d
    movd xmm1, xmm0
    mov rcx, rsi
    mov rdx, rdi
    movd r8, xmm1
    call RawrXD_SampleTemperature

    ; 2. Apply softmax
    mov rcx, rsi
    mov rdx, rdi
    shl rdx, 2
    call RawrXD_Softmax

    ; 3. Apply Top-K
    mov rcx, rsi
    mov rdx, rdi
    mov r8, r9
    call RawrXD_SampleTopK

    ; 4. Apply Top-P
    mov rcx, rsi
    mov rdx, rdi
    movss xmm0, DWORD PTR [rbp + 48]
    movd r8, xmm0
    call RawrXD_SampleTopP

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

RawrXD_Logits_Process ENDP

; =============================================================================
; RawrXD_Generation_Run - Run generation loop
;
; Parameters:
;   RCX = QWORD* prompt_tokens
;   RDX = QWORD prompt_len
;   R8  = QWORD max_tokens
;   R9  = QWORD* output_tokens
;
; Returns: RAX = number of tokens generated
; =============================================================================
RawrXD_Generation_Run PROC FRAME
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
    test r9, r9
    jz @@error

    mov rsi, rcx                    ; prompt_tokens
    mov rdi, rdx                    ; prompt_len
    mov r12, r8                     ; max_tokens
    mov r13, r9                     ; output_tokens

    ; Check model is loaded
    cmp BYTE PTR [g_ModelCtx + MODEL_CTX_LOADED], 0
    je @@error

    ; Reset position
    mov QWORD PTR [g_ModelCtx + MODEL_CTX_CUR_POS], 0

    ; Prefill: process prompt tokens
    xor r14, r14

@@prefill_loop:
    cmp r14, rdi
    jge @@decode

    mov rcx, QWORD PTR [rsi + r14*8]
    lea rdx, QWORD PTR [rbp - 8]
    call RawrXD_RunInference

    inc r14
    jmp @@prefill_loop

@@decode:
    ; Decode: generate new tokens
    mov r15, QWORD PTR [rbp - 8]   ; last token
    xor r14, r14

@@decode_loop:
    cmp r14, r12
    jge @@done

    mov rcx, r15
    lea rdx, QWORD PTR [rbp - 8]
    call RawrXD_RunInference

    mov rax, QWORD PTR [rbp - 8]
    mov QWORD PTR [r13 + r14*8], rax
    mov r15, rax

    inc r14
    jmp @@decode_loop

@@done:
    mov rax, r14
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

RawrXD_Generation_Run ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_DefEps            REAL4 1.0e-5
g_RopeTheta         REAL4 10000.0

END
