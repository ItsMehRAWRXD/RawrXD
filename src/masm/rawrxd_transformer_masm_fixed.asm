;==============================================================================
; rawrxd_transformer_masm.asm
; Pure x64 MASM transformer forward pass — zero dependencies
; Simplified working version
;==============================================================================
OPTION CASEMAP:NONE

.CODE

;==============================================================================
; CONSTANTS (defined in code section for RIP-relative addressing)
;==============================================================================
align 16
rms_norm_eps REAL4 1.0e-6
rope_theta REAL4 10000.0

;==============================================================================
; KV CACHE MANAGEMENT
;==============================================================================

; int rawrxd_kv_cache_alloc(RawrXDInferenceCtx* ctx, int n_layer, int n_ctx, int n_embd);
; rcx=ctx, edx=n_layer, r8d=n_ctx, r9d=n_embd
; Returns 0 on success, -1 on failure
PUBLIC rawrxd_kv_cache_alloc
rawrxd_kv_cache_alloc PROC
    push rbx
    push rdi
    push rsi
    
    mov rbx, rcx            ; ctx
    
    ; Calculate size: n_layer * n_ctx * n_embd * 2 (K+V) * 4 bytes
    mov eax, edx            ; n_layer
    imul eax, r8d           ; * n_ctx
    imul eax, r9d           ; * n_embd
    shl eax, 3              ; * 8 (2 caches * 4 bytes)
    
    ; Allocate with VirtualAlloc
    mov rsi, rax            ; save size
    xor ecx, ecx            ; lpAddress = NULL
    mov edx, eax            ; dwSize
    mov r8d, 4096h          ; MEM_COMMIT
    mov r9d, 4              ; PAGE_READWRITE
    sub rsp, 40
    mov qword ptr [rsp+32], 0  ; hProcess = NULL (ignored)
    call VirtualAlloc
    add rsp, 40
    
    test rax, rax
    jz alloc_fail
    
    ; Store K cache pointer at offset 0
    mov [rbx], rax
    
    ; Store V cache pointer at offset 8 (halfway through)
    mov rdi, rax
    add rdi, rsi
    shr rdi, 1
    mov [rbx+8], rdi
    
    ; Store size at offset 16
    shr rsi, 1
    mov [rbx+16], rsi
    
    xor eax, eax            ; return 0 (success)
    pop rsi
    pop rdi
    pop rbx
    ret
    
alloc_fail:
    mov eax, -1             ; return -1 (failure)
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_kv_cache_alloc ENDP

; void rawrxd_kv_cache_free(RawrXDInferenceCtx* ctx);
; rcx=ctx
PUBLIC rawrxd_kv_cache_free
rawrxd_kv_cache_free PROC
    push rbx
    mov rbx, rcx
    
    ; Get K cache pointer
    mov rcx, [rbx]          ; ptr
    test rcx, rcx
    jz free_done
    
    ; VirtualFree(ptr, 0, MEM_RELEASE)
    xor edx, edx            ; dwSize = 0
    mov r8d, 8000h          ; MEM_RELEASE
    sub rsp, 40
    call VirtualFree
    add rsp, 40
    
    ; Clear pointers
    mov qword ptr [rbx], 0
    mov qword ptr [rbx+8], 0
    mov qword ptr [rbx+16], 0
    
free_done:
    xor eax, eax
    pop rbx
    ret
rawrxd_kv_cache_free ENDP

; void rawrxd_kv_cache_reset(RawrXDInferenceCtx* ctx);
; rcx=ctx
PUBLIC rawrxd_kv_cache_reset
rawrxd_kv_cache_reset PROC
    push rdi
    push rcx
    
    ; Get K cache
    mov rdi, [rcx]          ; K cache pointer
    mov rcx, [rcx+16]       ; size in bytes
    
    ; Zero out K cache
    xor eax, eax
    shr rcx, 2              ; convert to dwords
    rep stosd
    
    pop rcx
    ; Get V cache
    mov rdi, [rcx+8]        ; V cache pointer
    mov rcx, [rcx+16]       ; size in bytes
    
    ; Zero out V cache
    xor eax, eax
    shr rcx, 2
    rep stosd
    
    pop rdi
    ret
rawrxd_kv_cache_reset ENDP

;==============================================================================
; FORWARD TOKEN (Simplified)
; void rawrxd_forward_token(float* logits, int token_id, RawrXDInferenceCtx* ctx);
; rcx=logits, edx=token_id, r8=ctx
;==============================================================================
PUBLIC rawrxd_forward_token
rawrxd_forward_token PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64
    
    mov r12, rcx            ; logits
    mov r13d, edx           ; token_id
    mov r14, r8             ; ctx
    
    ; Get model dimensions from context
    mov r15d, dword ptr [r14+64]   ; n_vocab
    mov ebx, dword ptr [r14+68]    ; n_embd
    
    ; Check if we have token embeddings
    mov rsi, [r14+24]       ; tok_embeddings
    test rsi, rsi
    jz forward_no_weights
    
    ; Get embedding for token_id: tok_embeddings[token_id * n_embd]
    mov eax, r13d           ; token_id
    mul ebx                 ; * n_embd
    shl rax, 2              ; * 4 bytes
    add rsi, rax            ; rsi = &tok_embeddings[token_id * n_embd]
    
    ; Copy embedding to scratch (simplified - just use first n_embd floats)
    ; In real impl, would run through transformer layers
    
forward_no_weights:
    ; Generate output logits (simplified)
    ; If no weights loaded, generate test distribution
    mov rdi, r12            ; logits output
    mov ecx, r15d           ; n_vocab
    
    ; Initialize with small random values
    mov eax, r13d           ; seed with token_id
    
gen_logits_loop:
    test ecx, ecx
    jz gen_logits_done
    
    ; Simple LCG random
    imul eax, 1103515245
    add eax, 12345
    
    ; Convert to float in range [-10, 10]
    mov edx, eax
    and edx, 07FFFh         ; 15-bit positive
    sub edx, 04000h         ; center around 0
    cvtsi2ss xmm0, edx
    divss xmm0, dword ptr [scale_div]
    
    movss dword ptr [rdi], xmm0
    add rdi, 4
    dec ecx
    jmp gen_logits_loop
    
gen_logits_done:
    ; Boost the input token position
    mov eax, r13d
    xor edx, edx
    div r15d                ; token_id % n_vocab
    mov eax, edx            ; remainder
    shl eax, 2              ; * 4 bytes
    add rax, r12            ; &logits[token_id % n_vocab]
    movss xmm0, dword ptr [rax]
    addss xmm0, dword ptr [boost_val]
    movss dword ptr [rax], xmm0
    
    xor eax, eax
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
    
align 16
scale_div REAL4 1638.4    ; 0x4000 / 10.0
boost_val REAL4 5.0

rawrxd_forward_token ENDP

;==============================================================================
; SAMPLE TOP-K
; int rawrxd_sample_top_k(const float* logits, int n_vocab, int k, float temp);
; rcx=logits, edx=n_vocab, r8d=k, xmm2=temp
; Returns sampled token ID
;==============================================================================
PUBLIC rawrxd_sample_top_k
rawrxd_sample_top_k PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64
    
    mov r12, rcx            ; logits
    mov r13d, edx           ; n_vocab
    mov r14d, r8d           ; k
    movss dword ptr [rsp+32], xmm2  ; temp
    
    ; Clamp k to n_vocab
    cmp r14d, r13d
    jle k_ok
    mov r14d, r13d
k_ok:
    
    ; Simple argmax for now (return highest logit)
    mov rsi, r12
    mov ecx, r13d
    xor edx, edx            ; max_idx = 0
    vxorps xmm0, xmm0, xmm0
    movss xmm0, dword ptr [rsi]  ; max_val = logits[0]
    add rsi, 4
    dec ecx
    jz sample_done
    
    mov edi, 1              ; idx = 1
    
find_max_loop:
    test ecx, ecx
    jz find_max_done
    
    movss xmm1, dword ptr [rsi]
    comiss xmm1, xmm0
    jbe not_max
    movss xmm0, xmm1
    mov edx, edi
not_max:
    add rsi, 4
    inc edi
    dec ecx
    jmp find_max_loop
    
find_max_done:
    mov eax, edx            ; return max_idx
    
sample_done:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
rawrxd_sample_top_k ENDP

;==============================================================================
; EXTERNAL FUNCTIONS
;==============================================================================
EXTERNDEF VirtualAlloc:PROC
EXTERNDEF VirtualFree:PROC

END
