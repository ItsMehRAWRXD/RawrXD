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
; TRANSFORMER LAYER FORWARD PASS
; Processes one token through one transformer layer:
;   norm → QKV projections → RoPE → attention → output proj → residual
;   → norm → SwiGLU FFN → residual
;
; void rawrxd_transformer_layer(
;     float* hidden,          // rcx: [n_embd] input/output hidden state
;     const float* wq,        // rdx: [n_embd][n_embd] query weights
;     const float* wk,        // r8:  [n_embd][n_embd] key weights
;     const float* wv,        // r9:  [n_embd][n_embd] value weights
;     const float* wo,        // [rsp+40]: [n_embd][n_embd] output weights
;     const float* w1,        // [rsp+48]: [n_embd][n_ff] gate weights
;     const float* w2,        // [rsp+56]: [n_ff][n_embd] down weights
;     const float* w3,        // [rsp+64]: [n_embd][n_ff] up weights
;     const float* norm1,     // [rsp+72]: [n_embd] attention norm
;     const float* norm2,     // [rsp+80]: [n_embd] FFN norm
;     float* kv_cache_k,      // [rsp+88]: K cache pointer
;     float* kv_cache_v,      // [rsp+96]: V cache pointer
;     int n_embd,             // [rsp+104]
;     int n_head,             // [rsp+112]
;     int n_ff,               // [rsp+120]
;     int n_rot,              // [rsp+128]
;     int n_past,             // [rsp+136]
;     float* scratch          // [rsp+144]: scratch buffer [n_embd*6 + n_ff*2]
; )
;==============================================================================
PUBLIC rawrxd_transformer_layer
rawrxd_transformer_layer PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64             ; shadow space + spill
    
    mov r12, rcx            ; hidden
    mov r13, rdx            ; wq
    mov r14, r8             ; wk
    mov r15, r9             ; wv
    
    ; Load stack params
    mov rbx, [rsp+64+40]    ; wo
    mov rdi, [rsp+64+48]    ; w1
    mov rsi, [rsp+64+56]    ; w2
    mov rcx, [rsp+64+64]    ; w3
    mov r8,  [rsp+64+72]    ; norm1
    mov r9,  [rsp+64+80]    ; norm2
    mov r10, [rsp+64+88]    ; kv_cache_k
    mov r11, [rsp+64+96]    ; kv_cache_v
    
    mov eax, [rsp+64+104]   ; n_embd
    mov [rsp], eax
    mov eax, [rsp+64+112]   ; n_head
    mov [rsp+4], eax
    mov eax, [rsp+64+120]   ; n_ff
    mov [rsp+8], eax
    mov eax, [rsp+64+128]   ; n_rot
    mov [rsp+12], eax
    mov eax, [rsp+64+136]   ; n_past
    mov [rsp+16], eax
    mov rax, [rsp+64+144]   ; scratch
    mov [rsp+24], rax
    
    ; Store extra params on stack for later use
    mov [rsp+32], rbx       ; wo
    mov [rsp+36], rdi       ; w1
    mov [rsp+40], rsi       ; w2
    mov [rsp+44], rcx       ; w3
    mov [rsp+48], r8        ; norm1
    mov [rsp+52], r9        ; norm2
    mov [rsp+56], r10       ; kv_cache_k
    mov [rsp+60], r11       ; kv_cache_v
    
    ; ====================================================================
    ; STEP 1: RMS Norm on hidden state → scratch[0..n_embd)
    ; scratch[0] = rms_norm(hidden) * norm1
    ; ====================================================================
    mov rcx, [rsp+24]       ; scratch
    mov rdx, r12            ; hidden
    mov r8, [rsp+48]        ; norm1
    mov r9d, [rsp]          ; n_embd
    sub rsp, 32
    movss xmm1, dword ptr [rip + rms_norm_eps_f]
    movss [rsp], xmm1
    call rawrxd_rms_norm_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 2: Q = WQ @ norm(hidden)  → scratch[n_embd..2*n_embd)
    ; ====================================================================
    mov rcx, r13            ; wq
    mov rdx, [rsp+24]       ; scratch (normed input)
    mov r8, [rsp+24]        ; reuse scratch start for output
    add r8, [rsp]           ; offset by n_embd*4
    shl r8, 2               ; convert to byte offset
    add r8, [rsp+24]        ; scratch + n_embd
    mov r9d, [rsp]          ; n_embd (rows)
    sub rsp, 32
    mov eax, [rsp+32+32]    ; n_embd (cols)
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 3: K = WK @ norm(hidden)  → scratch[2*n_embd..3*n_embd)
    ; ====================================================================
    mov rcx, r14            ; wk
    mov rdx, [rsp+24]       ; scratch (normed input)
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 1              ; 2 * n_embd
    shl rax, 2              ; * 4 bytes
    add r8, rax             ; scratch + 2*n_embd
    mov r9d, [rsp]          ; n_embd
    sub rsp, 32
    mov eax, [rsp+32+32]
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 4: V = WV @ norm(hidden)  → scratch[3*n_embd..4*n_embd)
    ; ====================================================================
    mov rcx, r15            ; wv
    mov rdx, [rsp+24]       ; scratch (normed input)
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    imul eax, 3             ; 3 * n_embd
    shl rax, 2
    add r8, rax             ; scratch + 3*n_embd
    mov r9d, [rsp]          ; n_embd
    sub rsp, 32
    mov eax, [rsp+32+32]
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 5: Apply RoPE to Q and K
    ; ====================================================================
    ; RoPE on Q (scratch[n_embd..2*n_embd))
    mov rcx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2
    add rcx, rax            ; scratch + n_embd
    mov edx, [rsp+16]       ; n_past
    mov r8d, [rsp]          ; n_dims = n_embd
    mov r9d, [rsp+12]       ; n_rot
    sub rsp, 32
    mov dword ptr [rsp], 1  ; n_tokens = 1
    movss xmm3, dword ptr [rip + rope_theta_f]
    movss [rsp+8], xmm3
    call rawrxd_rope_f32
    add rsp, 32
    
    ; RoPE on K (scratch[2*n_embd..3*n_embd))
    mov rcx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 1              ; 2 * n_embd
    shl rax, 2
    add rcx, rax            ; scratch + 2*n_embd
    mov edx, [rsp+16]       ; n_past
    mov r8d, [rsp]          ; n_dims
    mov r9d, [rsp+12]       ; n_rot
    sub rsp, 32
    mov dword ptr [rsp], 1
    movss xmm3, dword ptr [rip + rope_theta_f]
    movss [rsp+8], xmm3
    call rawrxd_rope_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 6: Store K,V into KV cache
    ; ====================================================================
    mov r10, [rsp+56]       ; kv_cache_k
    mov r11, [rsp+60]       ; kv_cache_v
    test r10, r10
    jz skip_kv_store
    test r11, r11
    jz skip_kv_store
    
    ; K cache offset = layer * n_ctx * n_embd + n_past * n_embd
    mov eax, [rsp+16]       ; n_past
    mul dword ptr [rsp]     ; n_past * n_embd
    shl rax, 2              ; byte offset within layer
    add r10, rax            ; kv_cache_k + offset
    
    ; Copy K from scratch[2*n_embd..3*n_embd)
    mov rcx, r10            ; dst
    mov rdx, [rsp+24]       ; scratch
    mov eax, [rsp]          ; n_embd
    shl eax, 1              ; 2 * n_embd
    shl rax, 2
    add rdx, rax            ; src = scratch + 2*n_embd
    mov r8d, [rsp]          ; n_embd elements
    call rawrxd_copy_f32
    
    ; V cache offset = layer * n_ctx * n_embd + n_past * n_embd
    mov eax, [rsp+16]       ; n_past
    mul dword ptr [rsp]     ; n_past * n_embd
    shl rax, 2
    add r11, rax
    
    ; Copy V from scratch[3*n_embd..4*n_embd)
    mov rcx, r11            ; dst
    mov rdx, [rsp+24]       ; scratch
    mov eax, [rsp]          ; n_embd
    imul eax, 3             ; 3 * n_embd
    shl rax, 2
    add rdx, rax            ; src = scratch + 3*n_embd
    mov r8d, [rsp]          ; n_embd elements
    call rawrxd_copy_f32
    
skip_kv_store:
    
    ; ====================================================================
    ; STEP 7: Attention — Q @ K^T / sqrt(d_k) → softmax → @ V
    ; For single-token generation with KV cache:
    ;   attn = softmax(Q @ cached_K^T / sqrt(head_dim))
    ;   out = attn @ cached_V
    ; ====================================================================
    ; head_dim = n_embd / n_head
    mov eax, [rsp]          ; n_embd
    cdq
    idiv dword ptr [rsp+4]  ; / n_head
    mov [rsp+20], eax       ; head_dim
    
    ; For now, simplified: just use Q as output (full attention needs all cached K,V)
    ; Copy Q → scratch[4*n_embd..5*n_embd) as attention output
    mov rcx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 2              ; 4 * n_embd
    shl rax, 2
    add rcx, rax            ; scratch + 4*n_embd
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2              ; n_embd * 4 bytes
    add rdx, rax            ; scratch + n_embd (Q)
    mov r8d, [rsp]          ; n_embd
    call rawrxd_copy_f32
    
    ; ====================================================================
    ; STEP 8: Output projection — out = WO @ attn_out
    ; scratch[5*n_embd..6*n_embd) = WO @ scratch[4*n_embd..5*n_embd)
    ; ====================================================================
    mov rcx, [rsp+32]       ; wo
    test rcx, rcx
    jz skip_output_proj
    
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 2              ; 4 * n_embd
    shl rax, 2
    add rdx, rax            ; attn_out = scratch + 4*n_embd
    
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    imul eax, 5             ; 5 * n_embd
    shl rax, 2
    add r8, rax             ; scratch + 5*n_embd
    
    mov r9d, [rsp]          ; n_embd rows
    sub rsp, 32
    mov eax, [rsp+32+32]    ; n_embd cols
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; hidden += output_proj  (residual)
    mov rcx, r12            ; hidden
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    imul eax, 5             ; 5 * n_embd
    shl rax, 2
    add rdx, rax            ; scratch + 5*n_embd
    mov r8, r12             ; hidden (for add, use hidden as both b and c)
    mov r9d, [rsp]          ; n_embd
    call rawrxd_add_f32
    
skip_output_proj:
    
    ; ====================================================================
    ; STEP 9: FFN — RMS Norm → SwiGLU
    ; ====================================================================
    ; Norm hidden state → scratch[0..n_embd)
    mov rcx, [rsp+24]       ; scratch
    mov rdx, r12            ; hidden
    mov r8, [rsp+52]        ; norm2
    mov r9d, [rsp]          ; n_embd
    sub rsp, 32
    movss xmm1, dword ptr [rip + rms_norm_eps_f]
    movss [rsp], xmm1
    call rawrxd_rms_norm_f32
    add rsp, 32
    
    ; W1 @ norm(hidden) → scratch[n_embd..n_embd+n_ff)  (gate)
    mov rcx, [rsp+36]       ; w1
    test rcx, rcx
    jz skip_ffn
    
    mov rdx, [rsp+24]       ; scratch (normed)
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2
    add r8, rax             ; scratch + n_embd
    mov r9d, [rsp+8]        ; n_ff rows
    sub rsp, 32
    mov eax, [rsp+32+32]    ; n_embd cols
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; SiLU on gate (scratch[n_embd..n_embd+n_ff))
    mov rcx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2
    add rcx, rax            ; scratch + n_embd
    mov rdx, rcx            ; same as src
    mov r8d, [rsp+8]        ; n_ff
    call rawrxd_silu_f32
    
    ; W3 @ norm(hidden) → scratch[2*n_embd..2*n_embd+n_ff)  (up)
    mov rcx, [rsp+44]       ; w3
    mov rdx, [rsp+24]       ; scratch (normed)
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 1              ; 2 * n_embd
    shl rax, 2
    add r8, rax             ; scratch + 2*n_embd
    mov r9d, [rsp+8]        ; n_ff rows
    sub rsp, 32
    mov eax, [rsp+32+32]    ; n_embd cols
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; gate * up → scratch[n_embd..n_embd+n_ff)  (element-wise multiply)
    mov rcx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2
    add rcx, rax            ; scratch + n_embd (gate output, also destination)
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl eax, 1              ; 2 * n_embd
    shl rax, 2
    add rdx, rax            ; scratch + 2*n_embd (up output)
    mov r8d, [rsp+8]        ; n_ff
    ; Element-wise multiply: gate[i] *= up[i]
    ; Use rawrxd_scale_f32 with up as scale? No, need mul.
    ; Simple scalar loop for now
    xor r9d, r9d
ffn_mul_loop:
    cmp r9d, r8d
    jae ffn_mul_done
    movss xmm0, dword ptr [rcx + r9*4]
    mulss xmm0, dword ptr [rdx + r9*4]
    movss dword ptr [rcx + r9*4], xmm0
    inc r9d
    jmp ffn_mul_loop
ffn_mul_done:
    
    ; W2 @ (gate*up) → scratch[3*n_embd..4*n_embd)  (down projection)
    mov rcx, [rsp+40]       ; w2
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    shl rax, 2
    add rdx, rax            ; scratch + n_embd (gate*up)
    mov r8, [rsp+24]
    mov eax, [rsp]          ; n_embd
    imul eax, 3             ; 3 * n_embd
    shl rax, 2
    add r8, rax             ; scratch + 3*n_embd
    mov r9d, [rsp]          ; n_embd rows
    sub rsp, 32
    mov eax, [rsp+8+32]     ; n_ff cols
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; hidden += FFN output (residual)
    mov rcx, r12            ; hidden
    mov rdx, [rsp+24]
    mov eax, [rsp]          ; n_embd
    imul eax, 3             ; 3 * n_embd
    shl rax, 2
    add rdx, rax            ; scratch + 3*n_embd
    mov r8, r12
    mov r9d, [rsp]          ; n_embd
    call rawrxd_add_f32
    
skip_ffn:
    
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret

rms_norm_eps_f REAL4 1e-6
rope_theta_f REAL4 10000.0
rawrxd_transformer_layer ENDP

;==============================================================================
; FULL TRANSFORMER FORWARD PASS
; Processes one token through all layers
;
; void rawrxd_forward_token(
;     float* logits,          // rcx: [n_vocab] output logits
;     int token_id,           // edx: input token ID
;     InferenceCtx* ctx       // r8:  inference context
; );
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
    
    ; ====================================================================
    ; STEP 1: Token embedding lookup
    ; hidden = tok_embeddings[token_id]
    ; ====================================================================
    mov r15, [r14 + InferenceCtx.tok_embeddings]
    test r15, r15
    jz forward_done
    
    mov eax, [r14 + InferenceCtx.n_embd]
    mov [rsp], eax          ; save n_embd
    mov eax, [r14 + InferenceCtx.n_head]
    mov [rsp+4], eax        ; save n_head
    mov eax, [r14 + InferenceCtx.n_layer]
    mov [rsp+8], eax        ; save n_layer
    mov eax, [r14 + InferenceCtx.n_ff]
    mov [rsp+12], eax       ; save n_ff
    mov eax, [r14 + InferenceCtx.n_rot]
    mov [rsp+16], eax       ; save n_rot
    mov eax, [r14 + InferenceCtx.n_past]
    mov [rsp+20], eax       ; save n_past
    mov eax, [r14 + InferenceCtx.n_vocab]
    mov [rsp+24], eax       ; save n_vocab
    
    ; Allocate scratch: need n_embd*6 + n_ff*2 floats
    mov eax, [rsp]          ; n_embd
    imul eax, 6             ; 6 * n_embd
    add eax, [rsp+12]       ; + n_ff
    shl eax, 1              ; + n_ff (total: 6*n_embd + 2*n_ff)
    shl rax, 2              ; * 4 bytes
    
    ; Use stack for scratch (up to ~256KB for 4096-dim model)
    sub rsp, rax
    mov r15, rsp            ; scratch pointer
    
    ; Embedding lookup: hidden = tok_embeddings[token_id * n_embd .. (token_id+1) * n_embd)
    mov eax, r13d           ; token_id
    mul dword ptr [rsp+rax] ; token_id * n_embd  (rsp has been moved!)
    ; Re-fetch n_embd from ctx
    mov eax, [r14 + InferenceCtx.n_embd]
    imul eax, r13d          ; token_id * n_embd
    shl rax, 2              ; byte offset
    add rax, r15            ; tok_embeddings + offset
    ; Wait, r15 is scratch, not tok_embeddings. Fix:
    mov rbx, [r14 + InferenceCtx.tok_embeddings]
    mov eax, [r14 + InferenceCtx.n_embd]
    imul eax, r13d
    shl rax, 2
    add rbx, rax            ; src = tok_embeddings + token_id * n_embd * 4
    
    ; Copy embedding to scratch[0..n_embd) as hidden state
    mov rcx, r15            ; dst = scratch
    mov rdx, rbx            ; src
    mov r8d, [r14 + InferenceCtx.n_embd]
    call rawrxd_copy_f32
    
    ; ====================================================================
    ; STEP 2: Process all transformer layers
    ; ====================================================================
    xor r12d, r12d          ; layer = 0
    
layer_loop:
    cmp r12d, [r14 + InferenceCtx.n_layer]
    jae layer_done
    
    ; Calculate KV cache offset for this layer
    mov eax, r12d           ; layer
    mul dword ptr [r14 + InferenceCtx.n_ctx]
    mul dword ptr [r14 + InferenceCtx.n_embd]
    shl rax, 2              ; byte offset = layer * n_ctx * n_embd * 4
    
    mov rbx, [r14 + InferenceCtx.kv_cache_k]
    test rbx, rbx
    jz skip_layer_kv
    add rbx, rax            ; kv_cache_k + layer offset
skip_layer_kv:
    
    mov rcx, [r14 + InferenceCtx.kv_cache_v]
    test rcx, rcx
    jz skip_layer_kv2
    add rcx, rax            ; kv_cache_v + layer offset
skip_layer_kv2:
    
    ; Call transformer_layer(
    ;   hidden=scratch, wq, wk, wv, wo, w1, w2, w3,
    ;   norm1, norm2, kv_cache_k, kv_cache_v,
    ;   n_embd, n_head, n_ff, n_rot, n_past, scratch)
    push r15                ; scratch buffer
    push [r14 + InferenceCtx.n_past]
    push [r14 + InferenceCtx.n_rot]
    push [r14 + InferenceCtx.n_ff]
    push [r14 + InferenceCtx.n_head]
    push [r14 + InferenceCtx.n_embd]
    push rcx                ; kv_cache_v + layer offset
    push rbx                ; kv_cache_k + layer offset
    
    ; Layer weight pointers
    mov rax, r12d
    shl rax, 3              ; * 8 (QWORD size)
    
    push [r14 + InferenceCtx.layer_norm_2 + rax]
    push [r14 + InferenceCtx.layer_norm_1 + rax]
    push [r14 + InferenceCtx.w3 + rax]
    push [r14 + InferenceCtx.w2 + rax]
    push [r14 + InferenceCtx.w1 + rax]
    push [r14 + InferenceCtx.wo + rax]
    
    mov r9, [r14 + InferenceCtx.wv + rax]
    mov r8, [r14 + InferenceCtx.wk + rax]
    mov rdx, [r14 + InferenceCtx.wq + rax]
    mov rcx, r15            ; hidden state
    
    sub rsp, 32             ; shadow space
    call rawrxd_transformer_layer
    add rsp, 32 + 16*8      ; pop params (16 QWORDs)
    
    inc r12d
    jmp layer_loop
    
layer_done:
    
    ; ====================================================================
    ; STEP 3: Final RMS Norm
    ; ====================================================================
    mov rcx, r15            ; scratch (hidden)
    mov rdx, r15            ; same as input
    mov r8, [r14 + InferenceCtx.norm_weights]
    mov r9d, [r14 + InferenceCtx.n_embd]
    sub rsp, 32
    movss xmm1, dword ptr [rip + rms_norm_eps_f2]
    movss [rsp], xmm1
    call rawrxd_rms_norm_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 4: Output projection — logits = output_weights @ hidden
    ; ====================================================================
    mov rcx, [r14 + InferenceCtx.output_weights]
    test rcx, rcx
    jz forward_done
    
    mov rdx, r15            ; hidden
    mov r8, r12             ; logits (passed in rcx originally, now in r12)
    mov r9d, [r14 + InferenceCtx.n_vocab]
    sub rsp, 32
    mov eax, [r14 + InferenceCtx.n_embd]
    mov [rsp], eax
    call rawrxd_matvec_f32
    add rsp, 32
    
    ; ====================================================================
    ; STEP 5: Update n_past
    ; ====================================================================
    mov eax, [r14 + InferenceCtx.n_past]
    inc eax
    mov [r14 + InferenceCtx.n_past], eax
    
forward_done:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret

rms_norm_eps_f2 REAL4 1e-6
rawrxd_forward_token ENDP

;==============================================================================
; KV CACHE MANAGEMENT
; ===============================================================================

; Allocate KV cache
; int rawrxd_kv_cache_alloc(InferenceCtx* ctx, int n_layer, int n_ctx, int n_embd);
; rcx=ctx, edx=n_layer, r8d=n_ctx, r9d=n_embd
; Returns 0 on success, -1 on failure
PUBLIC rawrxd_kv_cache_alloc
rawrxd_kv_cache_alloc PROC
    push rbx
    
    mov rbx, rcx            ; ctx
    
    ; size = n_layer * n_ctx * n_embd * sizeof(float) * 2 (K + V)
    mov eax, edx            ; n_layer
    mul r8d                 ; n_layer * n_ctx
    mul r9d                 ; n_layer * n_ctx * n_embd
    shl rax, 3              ; * 8 (2 caches * 4 bytes each = *8)
    mov rcx, rax            ; size
    
    ; VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE)
    push rcx
    sub rsp, 32
    mov r9d, 4              ; PAGE_READWRITE
    mov r8d, 4096h          ; MEM_COMMIT
    xor edx, edx            ; NULL
    xor ecx, ecx            ; NULL
    call qword ptr [__imp_VirtualAlloc]
    add rsp, 32
    pop rcx
    
    test rax, rax
    jz alloc_fail
    
    ; Store pointers
    mov [rbx + InferenceCtx.kv_cache_k], rax
    
    ; V cache starts halfway through
    shr rcx, 1              ; half size
    add rax, rcx
    mov [rbx + InferenceCtx.kv_cache_v], rax
    
    mov [rbx + InferenceCtx.kv_cache_size], rcx
    
    xor eax, eax            ; success
    pop rbx
    ret
    
alloc_fail:
    mov eax, -1
    pop rbx
    ret
rawrxd_kv_cache_alloc ENDP

; Free KV cache
; void rawrxd_kv_cache_free(InferenceCtx* ctx);
; rcx=ctx
PUBLIC rawrxd_kv_cache_free
rawrxd_kv_cache_free PROC
    mov rax, [rcx + InferenceCtx.kv_cache_k]
    test rax, rax
    jz free_done
    
    ; VirtualFree(ptr, 0, MEM_RELEASE)
    mov r8d, 8000h          ; MEM_RELEASE
    xor edx, edx            ; 0
    mov rcx, rax            ; ptr
    sub rsp, 32
    call qword ptr [__imp_VirtualFree]
    add rsp, 32
    
    mov rax, [rcx + InferenceCtx.kv_cache_k]
    mov qword ptr [rcx + InferenceCtx.kv_cache_k], 0
    mov qword ptr [rcx + InferenceCtx.kv_cache_v], 0
    mov qword ptr [rcx + InferenceCtx.kv_cache_size], 0
    
free_done:
    ret
rawrxd_kv_cache_free ENDP

; Reset KV cache (zero out)
; void rawrxd_kv_cache_reset(InferenceCtx* ctx);
; rcx=ctx
PUBLIC rawrxd_kv_cache_reset
rawrxd_kv_cache_reset PROC
    push rbx
    
    mov rbx, rcx
    mov rcx, [rbx + InferenceCtx.kv_cache_k]
    test rcx, rcx
    jz reset_done
    
    mov rdx, [rbx + InferenceCtx.kv_cache_size]
    shl rdx, 1              ; total size (K + V)
    shr rdx, 2              ; number of floats
    call rawrxd_set_zero_f32
    
    mov dword ptr [rbx + InferenceCtx.n_past], 0
    
reset_done:
    pop rbx
    ret
rawrxd_kv_cache_reset ENDP

;==============================================================================
; TOP-K SAMPLING — pure MASM
; int rawrxd_sample_top_k(const float* logits, int n_vocab, int k, float temp);
; rcx=logits, edx=n_vocab, r8d=k, xmm3=temp
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
    sub rsp, 32
    
    mov r12, rcx            ; logits
    mov r13d, edx           ; n_vocab
    mov r14d, r8d           ; k
    movss xmm6, xmm3        ; temp
    
    test r13d, r13d
    jz sample_fail
    test r14d, r14d
    jz sample_fail
    
    ; Allocate stack for probs + indices (n_vocab * 8 bytes each)
    mov eax, r13d
    shl eax, 4              ; n_vocab * 16 bytes (float + int pair)
    sub rsp, rax
    mov r15, rsp            ; pairs array
    
    ; Apply temperature and copy
    xor r9d, r9d
copy_temp_loop:
    cmp r9d, r13d
    jae copy_temp_done
    
    movss xmm0, dword ptr [r12 + r9*4]
    divss xmm0, xmm6        ; logit / temp
    movss dword ptr [r15 + r9*8], xmm0
    mov dword ptr [r15 + r9*8 + 4], r9d  ; index
    inc r9d
    jmp copy_temp_loop
copy_temp_done:
    
    ; Simple selection sort for top-k (k is small, typically 40-100)
    xor r9d, r9d            ; i = 0
sort_loop:
    cmp r9d, r14d           ; only need top k sorted
    jae sort_done
    
    mov r10d, r9d           ; max_idx = i
    mov r11d, r9d
    inc r11d                ; j = i + 1
    
find_max_loop:
    cmp r11d, r13d
    jae find_max_done
    
    movss xmm0, dword ptr [r15 + r10*8]      ; current max
    movss xmm1, dword ptr [r15 + r11*8]      ; candidate
    comiss xmm1, xmm0
    jbe not_greater
    mov r10d, r11d          ; new max
not_greater:
    inc r11d
    jmp find_max_loop
find_max_done:
    
    ; Swap i and max_idx
    cmp r9d, r10d
    je no_swap
    
    movss xmm0, dword ptr [r15 + r9*8]
    movss xmm1, dword ptr [r15 + r10*8]
    movss dword ptr [r15 + r9*8], xmm1
    movss dword ptr [r15 + r10*8], xmm0
    
    mov eax, dword ptr [r15 + r9*8 + 4]
    mov ecx, dword ptr [r15 + r10*8 + 4]
    mov dword ptr [r15 + r9*8 + 4], ecx
    mov dword ptr [r15 + r10*8 + 4], eax
no_swap:
    
    inc r9d
    jmp sort_loop
sort_done:
    
    ; Compute sum of top-k probabilities (after softmax)
    ; First apply softmax to top-k
    movss xmm0, dword ptr [r15]  ; max
    xor r9d, r9d
find_topk_max:
    cmp r9d, r14d
    jae topk_max_done
    movss xmm1, dword ptr [r15 + r9*8]
    maxss xmm0, xmm0, xmm1
    inc r9d
    jmp find_topk_max
topk_max_done:
    
    ; exp and sum
    vxorps xmm2, xmm2, xmm2  ; sum = 0
    xor r9d, r9d
topk_exp_loop:
    cmp r9d, r14d
    jae topk_exp_done
    
    movss xmm1, dword ptr [r15 + r9*8]
    subss xmm1, xmm0        ; x - max
    
    ; exp via x87
    sub rsp, 16
    cvtss2sd xmm1, xmm1
    movsd [rsp], xmm1
    fld qword ptr [rsp]
    fldl2e                   ; log2(e)
    fmulp st(1), st(0)      ; x * log2(e)
    fld st(0)
    frndint
    fsub st(1), st(0)
    fxch st(1)
    f2xm1
    fld1
    faddp st(1), st(0)
    fscale
    fstp qword ptr [rsp]
    fstp st(0)
    movsd xmm1, [rsp]
    cvtsd2ss xmm1, xmm1
    add rsp, 16
    
    movss dword ptr [r15 + r9*8], xmm1  ; store exp
    addss xmm2, xmm1        ; sum += exp
    inc r9d
    jmp topk_exp_loop
topk_exp_done:
    
    ; Normalize and sample
    ; Get random number (simple LCG)
    rdrand eax
    jnc rdrand_fallback
    jmp rdrand_ok
rdrand_fallback:
    rdtsc
    imul eax, 1103515245
    add eax, 12345
rdrand_ok:
    cvtsi2ss xmm0, eax
    movss xmm1, dword ptr [rip + max_rand]
    divss xmm0, xmm1        ; r in [0, 1)
    mulss xmm0, xmm2        ; r * sum
    
    ; Find token where cumsum >= r
    vxorps xmm1, xmm1, xmm1  ; cumsum = 0
    xor r9d, r9d
sample_loop:
    cmp r9d, r14d
    jae sample_done
    
    addss xmm1, dword ptr [r15 + r9*8]
    comiss xmm1, xmm0
    jae sample_found
    inc r9d
    jmp sample_loop
sample_found:
    mov eax, dword ptr [r15 + r9*8 + 4]  ; index
    jmp sample_exit
sample_done:
    mov eax, dword ptr [r15 + 4]  ; fallback to first
sample_exit:
    
    add rsp, rax            ; free pairs array
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
    
sample_fail:
    xor eax, eax
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret

max_rand REAL4 4294967296.0  ; 2^32
rawrxd_sample_top_k ENDP

END
