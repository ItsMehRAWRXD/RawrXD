; =============================================================================
; inference_engine.asm - RawrXD Inference Engine
; =============================================================================
; The main inference loop that ties together:
;   GGUF loader -> Tensor runtime -> Transformer blocks -> Sampler -> Output
;
; Generation loop:
;   while (pos < max_tokens):
;     1. Tokenize prompt (first pass) or use last token
;     2. Embedding lookup
;     3. Run all transformer blocks
;     4. Sample next token from logits
;     5. Append to KV cache
;     6. Output token
;     7. pos++
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; External references (defined in sampler.asm)
; =============================================================================
EXTERN g_SampleTemperature:REAL4
EXTERN g_SampleTopK:QWORD
EXTERN g_SampleTopP:REAL4

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Inference context (512 bytes)
align 16
g_InferenceCtx         DB 512 DUP(0)

; Context field offsets
INF_CTX_MODEL_PTR      EQU 0
INF_CTX_N_LAYERS       EQU 8
INF_CTX_N_EMBED        EQU 16
INF_CTX_N_HEADS        EQU 24
INF_CTX_N_HEADS_KV     EQU 32
INF_CTX_HEAD_DIM       EQU 40
INF_CTX_N_CTX_LEN      EQU 48
INF_CTX_VOCAB_SIZE     EQU 56
INF_CTX_RMS_EPS        EQU 64
INF_CTX_CUR_POS        EQU 72
INF_CTX_MAX_TOKENS     EQU 80
INF_CTX_TEMPERATURE    EQU 88
INF_CTX_TOP_K          EQU 96
INF_CTX_TOP_P          EQU 104
INF_CTX_LOGITS_BUF     EQU 112
INF_CTX_EMBED_BUF      EQU 120
INF_CTX_HIDDEN_BUF     EQU 128
INF_CTX_OUTPUT_BUF     EQU 136

; Weight pointers (stored in model context)
align 8
g_WeightPtrs           DQ 64 DUP(0)  ; Up to 64 weight tensors

; Weight index constants
WEIGHT_TOKEN_EMB       EQU 0
WEIGHT_OUTPUT_NORM     EQU 1
WEIGHT_OUTPUT_WEIGHT  EQU 2
WEIGHT_ATTN_NORM      EQU 3   ; + layer * 8
WEIGHT_ATTN_Q         EQU 4
WEIGHT_ATTN_K         EQU 5
WEIGHT_ATTN_V         EQU 6
WEIGHT_ATTN_OUT       EQU 7
WEIGHT_FFN_NORM       EQU 8
WEIGHT_FFN_GATE       EQU 9
WEIGHT_FFN_UP         EQU 10
WEIGHT_FFN_DOWN       EQU 11

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_LoadModel - Load model and prepare for inference
;
; Parameters:
;   RCX = char* model_path - Path to .gguf file
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_LoadModel PROC FRAME
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

    mov rsi, rcx                    ; model_path

    ; Load GGUF file
    call GGUF_Load
    test rax, rax
    jz @@error
    mov QWORD PTR [g_InferenceCtx + INF_CTX_MODEL_PTR], rax

    ; Read model architecture parameters from metadata
    ; (In production, parse GGUF metadata KV pairs)
    ; For now, set reasonable defaults
    mov QWORD PTR [g_InferenceCtx + INF_CTX_N_LAYERS], 32
    mov QWORD PTR [g_InferenceCtx + INF_CTX_N_EMBED], 4096
    mov QWORD PTR [g_InferenceCtx + INF_CTX_N_HEADS], 32
    mov QWORD PTR [g_InferenceCtx + INF_CTX_N_HEADS_KV], 8
    mov QWORD PTR [g_InferenceCtx + INF_CTX_HEAD_DIM], 128
    mov QWORD PTR [g_InferenceCtx + INF_CTX_N_CTX_LEN], 4096
    mov QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE], 32000
    movss xmm0, DWORD PTR [g_DefRMSEps]
    movss DWORD PTR [g_InferenceCtx + INF_CTX_RMS_EPS], xmm0

    ; Allocate working buffers
    mov rax, QWORD PTR [g_InferenceCtx + INF_CTX_N_EMBED]
    shl rax, 2                      ; * 4 bytes
    mov r12, rax

    mov rcx, r12
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [g_InferenceCtx + INF_CTX_EMBED_BUF], rax

    mov rcx, r12
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_embed
    mov QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF], rax

    mov rcx, r12
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_hidden
    mov QWORD PTR [g_InferenceCtx + INF_CTX_OUTPUT_BUF], rax

    ; Allocate logits buffer
    mov rax, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    shl rax, 2
    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@free_output
    mov QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF], rax

    ; Initialize KV cache
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_N_CTX_LEN]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_N_LAYERS]
    mov r8, QWORD PTR [g_InferenceCtx + INF_CTX_N_HEADS_KV]
    mov r9, QWORD PTR [g_InferenceCtx + INF_CTX_HEAD_DIM]
    mov DWORD PTR [rsp + 32], 0     ; F32 (not quantized)
    call RawrXD_KVCacheCreate
    test rax, rax
    jnz @@free_logits

    ; Initialize kernel registry
    call RawrXD_InitKernelRegistry

    xor rax, rax
    jmp @@exit

@@free_logits:
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    call RawrXD_AlignedFree
@@free_output:
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_OUTPUT_BUF]
    call RawrXD_AlignedFree
@@free_hidden:
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF]
    call RawrXD_AlignedFree
@@free_embed:
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_EMBED_BUF]
    call RawrXD_AlignedFree
@@error:
    mov rax, 1

@@exit:
    add rsp, 64
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_LoadModel ENDP

; =============================================================================
; RawrXD_RunInference - Run a single forward pass
;
; Parameters:
;   RCX = QWORD token     - Input token ID
;   RDX = QWORD* out_token - Output token ID (sampled)
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_RunInference PROC FRAME
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
    sub rsp, 128
    .allocstack 128
    .endprolog

    test rdx, rdx
    jz @@error

    mov r12, rcx                    ; input token
    mov r13, rdx                    ; out_token pointer

    ; Get model dimensions
    mov r14, QWORD PTR [g_InferenceCtx + INF_CTX_N_EMBED]  ; hidden_dim
    mov r15, QWORD PTR [g_InferenceCtx + INF_CTX_N_LAYERS] ; n_layers

    ; Step 1: Embedding lookup
    ; embed = token_embedding[token]
    mov rcx, r12
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_EMBED_BUF]
    mov r8, r14
    call RawrXD_EmbeddingLookup

    ; Step 2: Run all transformer blocks
    xor r9, r9                      ; layer index

@@layer_loop:
    cmp r9, r15
    jge @@sample

    ; For each layer:
    ;   hidden = transformer_block(hidden)
    ; (In production, call RawrXD_TransformerBlock with proper weights)

    inc r9
    jmp @@layer_loop

@@sample:
    ; Step 3: Final RMSNorm
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_OUTPUT_BUF]
    mov r8, QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF]  ; reuse as weight
    mov r9, r14
    call RawrXD_RMSNorm

    ; Step 4: Output projection (logits)
    ; logits = output_weight * hidden_norm
    ; (In production, call RawrXD_MatMul_F32)

    ; Step 5: Apply temperature
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    movss xmm0, DWORD PTR [g_InferenceCtx + INF_CTX_TEMPERATURE]
    movd r8, xmm0
    call RawrXD_SampleTemperature

    ; Step 6: Apply softmax to get probabilities
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    shl rdx, 2                      ; Convert to bytes
    call RawrXD_Softmax

    ; Step 7: Apply Top-K
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    mov r8, QWORD PTR [g_InferenceCtx + INF_CTX_TOP_K]
    call RawrXD_SampleTopK

    ; Step 8: Apply Top-P
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    movss xmm0, DWORD PTR [g_InferenceCtx + INF_CTX_TOP_P]
    movd r8, xmm0
    call RawrXD_SampleTopP

    ; Step 9: Sample token
    mov rcx, QWORD PTR [g_InferenceCtx + INF_CTX_LOGITS_BUF]
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_VOCAB_SIZE]
    call RawrXD_SampleToken
    mov QWORD PTR [r13], rax        ; Store output token

    ; Step 10: Update KV cache
    mov rcx, 0                      ; layer 0
    mov rdx, QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF]
    mov r8, QWORD PTR [g_InferenceCtx + INF_CTX_HIDDEN_BUF]
    call RawrXD_KVCacheAppend

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_RunInference ENDP

; =============================================================================
; RawrXD_Generate - Generate tokens from a prompt
;
; Parameters:
;   RCX = QWORD* prompt_tokens - Input prompt tokens
;   RDX = QWORD prompt_len     - Prompt length
;   R8  = QWORD max_tokens     - Max tokens to generate
;   R9  = QWORD* output_tokens - Output buffer
;
; Returns: RAX = number of tokens generated
; =============================================================================
RawrXD_Generate PROC FRAME
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

    ; Set sampling parameters
    movss xmm0, DWORD PTR [g_SampleTemperature]
    movss DWORD PTR [g_InferenceCtx + INF_CTX_TEMPERATURE], xmm0
    mov rax, QWORD PTR [g_SampleTopK]
    mov QWORD PTR [g_InferenceCtx + INF_CTX_TOP_K], rax
    movss xmm0, DWORD PTR [g_SampleTopP]
    movss DWORD PTR [g_InferenceCtx + INF_CTX_TOP_P], xmm0

    ; Process prompt tokens (prefill)
    xor r14, r14                    ; token index

@@prompt_loop:
    cmp r14, rdi
    jge @@generation

    mov rcx, QWORD PTR [rsi + r14*8]
    lea rdx, QWORD PTR [rbp - 8]
    call RawrXD_RunInference

    inc r14
    jmp @@prompt_loop

@@generation:
    ; Generate new tokens
    mov r15, QWORD PTR [rbp - 8]   ; last token
    xor r14, r14

@@gen_loop:
    cmp r14, r12
    jge @@done

    mov rcx, r15
    lea rdx, QWORD PTR [rbp - 8]
    call RawrXD_RunInference

    mov rax, QWORD PTR [rbp - 8]
    mov QWORD PTR [r13 + r14*8], rax
    mov r15, rax

    inc r14
    jmp @@gen_loop

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

RawrXD_Generate ENDP

; =============================================================================
; RawrXD_EmbeddingLookup - Look up token embedding
;
; Parameters:
;   RCX = QWORD token
;   RDX = float* out
;   R8  = QWORD embed_dim
; =============================================================================
RawrXD_EmbeddingLookup PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; token
    mov rdi, rdx                    ; out
    mov rbx, r8                     ; embed_dim

    ; In production, look up from token_embedding weight tensor
    ; For now, zero the output
    mov rcx, rdi
    mov rdx, rbx
    shl rdx, 2
    call RawrXD_ZeroMemory

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    pop rdi
    pop rsi
    pop rbx
    ret

RawrXD_EmbeddingLookup ENDP

; =============================================================================
; RawrXD_StreamTokens - Callback-based token streaming
;
; Parameters:
;   RCX = QWORD* prompt_tokens
;   RDX = QWORD prompt_len
;   R8  = QWORD max_tokens
;   R9  = void* callback(token) - Callback for each generated token
; =============================================================================
RawrXD_StreamTokens PROC FRAME
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

    test r9, r9
    jz @@error

    mov rsi, rcx                    ; prompt_tokens
    mov rdi, rdx                    ; prompt_len
    mov r12, r8                     ; max_tokens
    mov r13, r9                     ; callback

    ; Allocate output buffer on stack
    mov rax, r12
    shl rax, 3
    sub rsp, rax
    mov r14, rsp                    ; output buffer

    ; Generate tokens
    mov rcx, rsi
    mov rdx, rdi
    mov r8, r12
    mov r9, r14
    call RawrXD_Generate
    mov r15, rax                    ; num_tokens

    ; Call callback for each token
    xor r9, r9

@@callback_loop:
    cmp r9, r15
    jge @@done
    mov rcx, QWORD PTR [r14 + r9*8]
    call r13                        ; callback(token)
    inc r9
    jmp @@callback_loop

@@done:
    mov rax, r15
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    mov rsp, rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_StreamTokens ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_DefRMSEps          REAL4 1.0e-5
g_DefTemperature     REAL4 0.8
g_DefTopP            REAL4 0.9
g_DefTopK            DQ 40

END
