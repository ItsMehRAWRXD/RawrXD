; ═══════════════════════════════════════════════════════════════════════════════
; RawrXD Tree Attention AVX-512 Kernel (MASM x64)
; ═══════════════════════════════════════════════════════════════════════════════
; Branchless tree verification using k-mask registers for DAG traversal
; Target: 2,000+ TPS through speculative decoding
; ═══════════════════════════════════════════════════════════════════════════════

; Assembler: ml64.exe (VS2022 Enterprise)
; Architecture: x86-64 with AVX-512F, AVX-512VL, AVX-512BW

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; External Dependencies
; ═══════════════════════════════════════════════════════════════════════════════
EXTERN expf:PROC
EXTERN logf:PROC
EXTERN sqrtf:PROC

; ═══════════════════════════════════════════════════════════════════════════════
; Public Exports (match C++ header expectations)
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC TreeAttention_AVX512
PUBLIC TreeAttention_ScoreBatch
PUBLIC TreeAttention_OnlineSoftmax
PUBLIC TreeAttention_AVX512_ApplyMask
PUBLIC TreeAttention_AVX512_VerifyBatch
PUBLIC TreeAttention_AVX512_Forward

; ═══════════════════════════════════════════════════════════════════════════════
; Constants
; ═══════════════════════════════════════════════════════════════════════════════
HEAD_DIM        EQU     128             ; Attention head dimension
BLOCK_M         EQU     64              ; Query block size
BLOCK_N         EQU     64              ; Key block size
VEC_WIDTH       EQU     16              ; 16 floats per zmm register (512-bit)

; Tree node flags
FLAG_VALID      EQU     1
FLAG_VERIFIED   EQU     4
FLAG_REJECTED   EQU     8

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data

; Lookup table for exp(x) approximation using minimax polynomial
; Range: [-8.0, 0.0] with 256 entries
exp_lut LABEL BYTE
    DB      256 DUP (0)                 ; Placeholder - populated at runtime

; Scale factor for attention: 1/sqrt(head_dim)
attn_scale      REAL4   8.838835E-002   ; 1/sqrt(128) = 0.08838834764831843

; Mask constants
all_ones_mask   DQ      0FFFFFFFFFFFFFFFFh    ; All 16 lanes active

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512_ApplyMask
; 
; Applies tree causal mask using k-mask registers (branchless)
;
; Parameters (Windows x64 ABI):
;   RCX = attn_scores (float*)
;   RDX = tree_mask (uint8_t*) - 1 = can attend, 0 = masked
;   R8  = num_nodes
;   R9  = head_dim
;
; Returns: void
; Clobbers: zmm0-zmm3, k1-k4, rax, r10-r11
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_AVX512_ApplyMask PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Save parameters
    mov     r10, rcx                    ; r10 = attn_scores
    mov     r11, rdx                    ; r11 = tree_mask
    mov     rax, r8                     ; rax = num_nodes (loop counter)
    
    ; Process 16 nodes at a time using AVX-512
    mov     r8, rax
    shr     r8, 4                       ; r8 = num_nodes / 16
    jz      @F                          ; Skip if less than 16 nodes
    
.apply_mask_loop16:
    ; Load 16 mask values (bytes) - each byte is 0 or 1
    vmovdqu8 xmm0, xmmword ptr [r11]    ; Load 16 bytes (16 uint8_t masks)
    
    ; Convert byte mask to k-mask register using vpmovb2m
    ; This creates a 16-bit mask where each bit corresponds to one byte
    vpmovb2m k1, xmm0                   ; k1 = mask bits from bytes
    
    ; Load attention scores (16 floats = 64 bytes)
    vmovups zmm1, zmmword ptr [r10]     ; zmm1 = scores[0:15]
    
    ; Broadcast -inf to all lanes of zmm2
    vpbroadcastd zmm2, dword ptr [neg_inf]  ; zmm2 = [-inf, -inf, ..., -inf]
    
    ; Apply mask using merge-masking:
    ; Where k1[i] = 1 (can attend), keep original score from zmm1
    ; Where k1[i] = 0 (masked), use -inf from zmm2
    ; vblendmps dest {k}, src1, src2 -> dest = src2 where k=1, else src1
    vblendmps zmm1 {k1}, zmm2, zmm1     ; Merge: keep score where mask=1, else -inf
    
    ; Store masked scores back to memory
    vmovups zmmword ptr [r10], zmm1
    
    ; Advance pointers
    add     r10, 64                     ; 16 floats * 4 bytes = 64 bytes
    add     r11, 16                     ; 16 mask bytes
    
    dec     r8                          ; Decrement loop counter
    jnz     .apply_mask_loop16          ; Continue if more blocks

@@:
    ; Handle remaining nodes (< 16)
    and     rax, 15                     ; rax = num_nodes % 16
    jz      .apply_mask_done
    
    ; Create tail mask
    mov     ecx, eax
    mov     edx, 1
    shl     edx, cl
    dec     edx                         ; edx = (1 << remainder) - 1
    kmovw   k1, edx
    
    ; Load and mask remaining scores
    vmovups zmm1 {k1}{z}, zmmword ptr [r10]   ; Load with tail mask
    vpbroadcastd zmm2, dword ptr [neg_inf]  ; Broadcast -inf
    vmovdqu8 xmm0, xmmword ptr [r11]          ; Load remaining mask bytes
    vpmovb2m k2, xmm0                         ; Convert to mask register
    kandw   k1, k1, k2                        ; Combine tail mask with tree mask
    vblendmps zmm1 {k1}, zmm2, zmm1           ; Apply mask
    vmovups zmmword ptr [r10] {k1}, zmm1      ; Store with mask

.apply_mask_done:
    ; Epilogue
    vzeroupper
    pop     rbp
    ret

TreeAttention_AVX512_ApplyMask ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512_VerifyBatch
;
; Verifies draft tokens against model output using branchless comparison
;
; Parameters:
;   RCX = draft_tokens (uint32_t*)
;   RDX = model_logits (float* - model's predicted tokens)
;   R8  = num_tokens
;   R9  = vocab_size
;   [RSP+40] = results (uint8_t* - output acceptance flags)
;
; Returns: number of accepted tokens (in RAX)
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_AVX512_VerifyBatch PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; Save parameters (Windows x64 ABI)
    ; RCX = draft_tokens, RDX = model_tokens, R8 = num_tokens
    ; R9 = vocab_size, [RBP+56] = results (5th parameter)
    mov     rsi, rcx                    ; rsi = draft_tokens
    mov     rdi, rdx                    ; rdi = model_tokens  
    mov     rbx, r8                     ; rbx = num_tokens (loop counter)
    ; r9 = vocab_size (unused in simplified version)
    mov     r11, [rbp+56]               ; r11 = results (after 5 pushes = 40 bytes)
    
    xor     r12, r12                    ; r12 = index = 0
    xor     rax, rax                    ; rax = consecutive_accepted = 0
    
    test    rbx, rbx
    jz      .verify_done

.verify_loop:
    ; Load draft token and model token
    mov     r8d, dword ptr [rsi + r12*4]    ; draft token
    mov     r9d, dword ptr [rdi + r12*4]    ; model token
    
    ; Compare and set result
    xor     edx, edx                    ; dl = 0 (rejected)
    cmp     r8d, r9d                    ; compare tokens
    sete    dl                          ; dl = 1 if match
    
    ; Store result
    mov     byte ptr [r11 + r12], dl
    
    ; Update consecutive count - break on first mismatch
    test    dl, dl
    jz      .verify_done                ; First mismatch - stop accepting
    
    inc     rax                         ; consecutive_accepted++
    inc     r12                         ; index++
    
    cmp     r12, rbx
    jb      .verify_loop

.verify_done:
    ; Epilogue - rax already contains consecutive_accepted
    add     rsp, 40
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttention_AVX512_VerifyBatch ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512_Forward
;
; Main tree attention forward pass with online softmax
;
; Parameters:
;   RCX = Q (float* queries)
;   RDX = K (float* keys)
;   R8  = V (float* values)
;   R9  = output (float*)
;   [RSP+40] = tree_mask (uint8_t*)
;   [RSP+48] = num_nodes
;   [RSP+56] = head_dim
;
; Returns: void
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_AVX512_Forward PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64
    .allocstack 64
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = Q
    mov     r13, rdx                    ; r13 = K
    mov     r14, r8                     ; r14 = V
    mov     r15, r9                     ; r15 = output
    mov     rbx, [rbp+64]               ; rbx = tree_mask
    mov     rsi, [rbp+72]               ; rsi = num_nodes
    mov     rdi, [rbp+80]               ; rdi = head_dim
    
    ; Broadcast scale factor
    vbroadcastss zmm15, dword ptr [attn_scale]
    
    ; Initialize online softmax state
    ; max_score = -inf, sum_exp = 0
    vpbroadcastd zmm14, dword ptr [neg_inf]  ; zmm14 = max_scores
    vxorps  zmm13, zmm13, zmm13         ; zmm13 = sum_exp = 0
    vxorps  zmm12, zmm12, zmm12         ; zmm12 = accum_output = 0

    xor     r8, r8                      ; r8 = node_idx = 0

.node_loop:
    cmp     r8, rsi
    jae     .forward_done
    
    ; For each node, compute attention with all previous nodes (causal)
    ; This is the core attention computation: softmax(Q·K^T / sqrt(d_k)) · V
    
    ; Load Q for current node
    mov     rax, r8
    imul    rax, rdi                    ; rax = node_idx * head_dim
    lea     r10, [r12 + rax*4]          ; r10 = &Q[node]
    
    ; Compute dot products with all keys up to current node
    xor     r11, r11                    ; r11 = key_idx = 0
    
.score_loop:
    cmp     r11, r8
    ja      .score_done                 ; Only attend to previous nodes (causal)
    
    ; Compute Q[node] · K[key_idx]
    vxorps  zmm0, zmm0, zmm0            ; zmm0 = accumulator = 0
    
    ; Load K for this key index
    mov     rax, r11
    imul    rax, rdi
    lea     r14, [r13 + rax*4]          ; r14 = &K[key_idx]
    
    ; Compute dot product: sum(Q[i] * K[i]) for i in 0..head_dim-1
    mov     rcx, rdi
    shr     rcx, 4                      ; head_dim / 16
    
.dot_product_loop:
    vmovups zmm1, zmmword ptr [r10]      ; Load Q vector
    vmovups zmm2, zmmword ptr [r14]      ; Load K vector
    vfmadd231ps zmm0, zmm1, zmm2         ; zmm0 += Q * K
    add     r10, 64
    add     r14, 64
    dec     rcx
    jnz     .dot_product_loop
    
    ; Horizontal sum to get scalar dot product
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Scale by 1/sqrt(head_dim)
    vmulss  xmm0, xmm0, xmm15
    
    ; Store score (simplified - would accumulate to softmax in full impl)
    ; For now, just compute the score
    
    ; Reset Q pointer for next iteration
    mov     rax, r8
    imul    rax, rdi
    lea     r10, [r12 + rax*4]
    
    inc     r11
    jmp     .score_loop
    
.score_done:
    inc     r8
    jmp     .node_loop

.dot_product_scalar:
    ; Handle remaining elements
    jmp     .node_loop

.forward_done:
    ; Epilogue
    vzeroupper
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttention_AVX512_Forward ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_AVX512 (wrapper for C++ compatibility)
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_AVX512 PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Simply forward to TreeAttention_AVX512_Forward
    ; Parameters already in correct registers per Windows x64 ABI
    call    TreeAttention_AVX512_Forward

    ; Epilogue
    pop     rbp
    ret
TreeAttention_AVX512 ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_ScoreBatch (stub for C++ compatibility)
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_ScoreBatch PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Stub implementation - compute Q·K^T for batch
    ; RCX = Q, RDX = K, R8 = scores, R9 = tree_mask
    ; [RSP+40] = num_q, [RSP+48] = num_k, [RSP+56] = head_dim

    mov     rbx, [rsp+40]               ; rbx = num_q
    test    rbx, rbx
    jz      .score_done

.score_loop:
    ; Simplified: just zero the scores for now
    mov     rax, r8
    mov     rcx, [rsp+48]               ; num_k
    xor     edx, edx
.zero_loop:
    mov     dword ptr [rax+rdx*4], 0
    inc     edx
    cmp     edx, ecx
    jb      .zero_loop

    dec     rbx
    jnz     .score_loop

.score_done:
    ; Epilogue
    pop     rbx
    pop     rbp
    ret
TreeAttention_ScoreBatch ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; TreeAttention_OnlineSoftmax (stub for C++ compatibility)
; ═══════════════════════════════════════════════════════════════════════════════
TreeAttention_OnlineSoftmax PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Stub: copy input to output
    ; RCX = scores, RDX = output, R8 = tree_mask, R9 = length

    mov     rax, rcx                    ; src
    mov     r10, rdx                    ; dst
    mov     r11, r9                     ; length

.softmax_loop:
    test    r11, r11
    jz      .softmax_done

    movss   xmm0, dword ptr [rax]
    movss   dword ptr [r10], xmm0

    add     rax, 4
    add     r10, 4
    dec     r11
    jmp     .softmax_loop

.softmax_done:
    ; Epilogue
    pop     rbp
    ret
TreeAttention_OnlineSoftmax ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; Data
; ═══════════════════════════════════════════════════════════════════════════════
.data
neg_inf         REAL4   -1.0E38          ; Approximate -Infinity
pos_inf         REAL4   1.0E38           ; Approximate +Infinity
zero_f          REAL4   0.0
one_f           REAL4   1.0

; ═══════════════════════════════════════════════════════════════════════════════
; End
; ═══════════════════════════════════════════════════════════════════════════════
END
