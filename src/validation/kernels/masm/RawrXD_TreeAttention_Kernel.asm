; ============================================================================
; RawrXD Tree Attention Kernel - AVX-512 Implementation
; VAL-032: Speculative Decoding Acceleration
;
; Target: Verify 16 draft tokens (4x4 tree) in single AVX-512 pass
; Expected latency: <500ns per tree verification
; ============================================================================

; x64 MASM directives
OPTION CASEMAP:NONE

.const

; Softmax polynomial constants
ALIGN 16
one REAL4 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
half REAL4 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5
one_sixth REAL4 0.166666667, 0.166666667, 0.166666667, 0.166666667, 0.166666667, 0.166666667, 0.166666667, 0.166666667
one_twenty_fourth REAL4 0.041666667, 0.041666667, 0.041666667, 0.041666667, 0.041666667, 0.041666667, 0.041666667, 0.041666667

; Softmax scale values for common head dimensions
; scale = 1/sqrt(head_dim)
ALIGN 16
scale_64_val REAL4 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125    ; 1/sqrt(64) = 0.125
scale_128_val REAL4 0.088388347, 0.088388347, 0.088388347, 0.088388347, 0.088388347, 0.088388347, 0.088388347, 0.088388347  ; 1/sqrt(128)

.data

; Softmax constants
ALIGN 16
exp_lut QWORD 256 DUP (0)           ; Lookup table for exp approximation
softmax_scale REAL4 1.0             ; 1/sqrt(head_dim)

; Tree mask patterns (pre-computed for 4x4 tree)
; Each bit represents whether node i can attend to node j
ALIGN 16
tree_mask_4x4 BYTE 256 DUP (0FFh)   ; All ones initially

.code

; -----------------------------------------------------------------------------
; TreeVerify_Batch_4x4_AVX512
; 
; Performs tree attention verification for 16 draft tokens (4x4 tree structure)
; 
; Parameters (Windows x64 ABI):
;   RCX = Q matrix pointer (16 x head_dim, 64-byte aligned)
;   RDX = K matrix pointer (16 x head_dim, 64-byte aligned)
;   R8  = V matrix pointer (16 x head_dim, 64-byte aligned)
;   R9  = Tree mask pointer (16 x 16 bytes, 64-byte aligned)
;   [RSP+40] = Output pointer (16 x head_dim, 64-byte aligned)
;   [RSP+48] = Head dimension (typically 64 or 128)
;   [RSP+56] = Softmax scale (1/sqrt(head_dim))
;
; Returns:
;   RAX = 0 on success, non-zero on error
; -----------------------------------------------------------------------------
PUBLIC TreeVerify_Batch_4x4_AVX512

TreeVerify_Batch_4x4_AVX512 PROC FRAME
    ; Save non-volatile registers
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    
    sub rsp, 256                    ; Allocate shadow space + local vars + score matrix
    .allocstack 256
    
    .endprolog
    
    ; Load parameters
    mov rbx, rcx                    ; RBX = Q pointer
    mov r12, rdx                    ; R12 = K pointer
    mov r13, r8                     ; R13 = V pointer
    mov r14, r9                     ; R14 = Tree mask pointer
    mov r15, QWORD PTR [rsp+296]    ; R15 = Output pointer (adjusted for larger stack)
    mov r8d, DWORD PTR [rsp+304]    ; R8D = Head dimension
    movss xmm0, REAL4 PTR [rsp+312]   ; XMM0 = Softmax scale
    vbroadcastss zmm31, xmm0        ; ZMM31 = scale broadcasted
    
    ; Constants
    mov eax, 16                     ; 16 nodes in 4x4 tree
    mov r9d, r8d
    shr r9d, 4                      ; R9 = head_dim / 16 (number of 512-bit chunks)
    
    ; =========================================================================
    ; Phase 1: Compute Q @ K^T (16x16 attention scores)
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = query node index (0-15)
    
query_loop:
    xor r11d, r11d                  ; R11 = key node index (0-15)
    
key_loop:
    ; Compute dot product Q[r10] . K[r11]
    vxorps zmm30, zmm30, zmm30      ; ZMM30 = accumulator
    
    xor eax, eax                    ; RAX = dimension chunk index (use RAX instead of R12)
    
dim_loop:
    ; Load K chunk - use r12 which holds K pointer
    push rax                        ; Save dim index
    mov rcx, r11
    imul rcx, r8                    ; RCX = r11 * head_dim
    shl rax, 6                      ; RAX = dim_idx * 64
    add rcx, rax
    vmovups zmm1, [r12 + rcx]       ; ZMM1 = K[r11][dim_idx*16:dim_idx*16+15]
    
    ; Load Q chunk
    mov rcx, r10
    imul rcx, r8
    add rcx, rax
    vmovups zmm2, [rbx + rcx]       ; ZMM2 = Q[r10][dim_idx*16:dim_idx*16+15]
    
    pop rax                         ; Restore dim index
    
    ; Fused multiply-add
    vfmadd231ps zmm30, zmm2, zmm1   ; ZMM30 += Q * K
    
    inc eax
    cmp eax, r9d
    jl dim_loop
    
    ; Horizontal sum of ZMM30
    vextractf64x4 ymm1, zmm30, 1    ; Extract high 256 bits
    vaddps ymm0, ymm30, ymm1        ; Combine
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Store score at rsp + r10*64 + r11*4
    mov rcx, r10
    shl rcx, 4                      ; RCX = r10 * 16
    add rcx, r11
    movss REAL4 PTR [rsp + rcx*4], xmm0
    
    inc r11d
    cmp r11d, 16
    jl key_loop
    
    inc r10d
    cmp r10d, 16
    jl query_loop
    
    ; =========================================================================
    ; Phase 2: Apply Tree Mask and Softmax
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = row index
    
softmax_row_loop:
    ; Load tree mask for this row
    mov rax, r10
    shl rax, 4                      ; RAX = r10 * 16
    vmovups xmm0, [r14 + rax]      ; XMM0 = mask[row] (16 bytes)
    vpmovzxbd zmm0, xmm0            ; Zero-extend to 32-bit
    vcvtdq2ps zmm0, zmm0            ; Convert to float (1.0 or 0.0)
    
    ; Load attention scores for this row
    vmovups zmm1, [rsp + rax*4]     ; ZMM1 = scores[row]
    
    ; Apply mask (multiply by 0 or 1)
    vmulps zmm1, zmm1, zmm0
    
    ; Scale by softmax_scale
    vmulps zmm1, zmm1, zmm31
    
    ; Find max for numerical stability
    vmaxps zmm2, zmm1, zmm1         ; ZMM2 = max (simplified)
    
    ; Subtract max and compute exp
    vsubps zmm1, zmm1, zmm2
    
    ; Approximate exp using polynomial
    ; exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24
    vmovups zmm3, zmm1              ; ZMM3 = x
    vmulps zmm4, zmm3, zmm3         ; ZMM4 = x^2
    vmulps zmm5, zmm4, zmm3         ; ZMM5 = x^3
    vmulps zmm6, zmm5, zmm3         ; ZMM6 = x^4
    
    vbroadcastss zmm7, REAL4 PTR [one]
    vbroadcastss zmm8, REAL4 PTR [half]
    vbroadcastss zmm9, REAL4 PTR [one_sixth]
    vbroadcastss zmm10, REAL4 PTR [one_twenty_fourth]
    
    vfmadd231ps zmm7, zmm3, zmm7    ; 1 + x
    vfmadd231ps zmm7, zmm4, zmm8    ; + x^2/2
    vfmadd231ps zmm7, zmm5, zmm9    ; + x^3/6
    vfmadd231ps zmm7, zmm6, zmm10   ; + x^4/24
    
    ; Sum for normalization
    vextractf64x4 ymm1, zmm7, 1
    vaddps ymm0, ymm7, ymm1
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Broadcast sum
    vbroadcastss zmm2, xmm0
    
    ; Normalize
    vdivps zmm7, zmm7, zmm2
    
    ; Store softmax output
    vmovups [rsp + rax*4 + 256], zmm7
    
    inc r10d
    cmp r10d, 16
    jl softmax_row_loop
    
    ; =========================================================================
    ; Phase 3: Compute Attention @ V (Output)
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = output row
    
output_row_loop:
    vxorps zmm30, zmm30, zmm30      ; ZMM30 = accumulator
    
    xor r11d, r11d                  ; R11 = column in V
    
v_col_loop:
    ; Load softmax weights for this row
    mov rax, r10
    shl rax, 4
    vmovups zmm0, [rsp + rax*4 + 256]
    
    ; Broadcast each weight and multiply by V
    ; Simplified: assume head_dim = 64 for now
    mov rax, r11
    imul rax, r8
    vmovups zmm1, [r13 + rax]       ; ZMM1 = V[r11]
    
    vmulps zmm2, zmm0, zmm1         ; ZMM2 = softmax_weight * V
    vaddps zmm30, zmm30, zmm2       ; Accumulate
    
    inc r11d
    cmp r11d, 16
    jl v_col_loop
    
    ; Store output row
    mov rax, r10
    imul rax, r8
    vmovups [r15 + rax], zmm30
    
    inc r10d
    cmp r10d, 16
    jl output_row_loop
    
    ; =========================================================================
    ; Cleanup and return
    ; =========================================================================
    
    vzeroall                        ; Clear all ZMM registers
    
    xor rax, rax                    ; Return 0 (success)
    
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    
TreeVerify_Batch_4x4_AVX512 ENDP

; -----------------------------------------------------------------------------
; Feature Detection
; -----------------------------------------------------------------------------
PUBLIC TreeAttention_HasAVX512

TreeAttention_HasAVX512 PROC
    ; Check CPUID for AVX-512 support
    mov eax, 1
    cpuid
    and ecx, 10000000h              ; Check bit 28 (AVX)
    jz no_avx512
    
    mov eax, 7
    xor ecx, ecx
    cpuid
    and ebx, 00010000h              ; Check bit 16 (AVX-512F)
    jz no_avx512
    
    mov eax, 1                      ; Return 1 (AVX-512 supported)
    ret
    
no_avx512:
    xor eax, eax                    ; Return 0 (not supported)
    ret
    
TreeAttention_HasAVX512 ENDP

; -----------------------------------------------------------------------------
; Get Optimal Thread Count
; -----------------------------------------------------------------------------
PUBLIC TreeAttention_GetOptimalThreads

TreeAttention_GetOptimalThreads PROC
    ; Get number of processors
    mov eax, 1
    cpuid
    and ebx, 00FF0000h              ; Extract bit 23-16 (logical processors)
    shr ebx, 16
    mov eax, ebx
    ret
    
TreeAttention_GetOptimalThreads ENDP

; ---------------------------------------------------------------------------
; C++ Interface Wrappers
; ---------------------------------------------------------------------------
PUBLIC TreeAttention_AVX512
PUBLIC TreeAttention_AVX512_VerifyBatch

; Wrapper for TreeAttention_AVX512 - matches C++ signature
TreeAttention_AVX512 PROC FRAME
    ; C++ signature: void TreeAttention_AVX512(const float* Q, const float* K, const float* V, 
    ;                                           float* output, const uint8_t* tree_mask,
    ;                                           uint32_t num_nodes, uint32_t head_dim)
    ; RCX = Q, RDX = K, R8 = V, R9 = output
    ; [RSP+40] = tree_mask, [RSP+48] = num_nodes, [RSP+56] = head_dim
    
    push rbp
    .pushreg rbp
    mov rbp, rsp
    push rbx
    .pushreg rbx
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
    
    ; Load parameters
    mov rbx, rcx                    ; RBX = Q
    mov r12, rdx                    ; R12 = K
    mov r13, r8                     ; R13 = V
    mov r14, r9                     ; R14 = output
    mov r15, QWORD PTR [rbp+48]     ; R15 = tree_mask
    mov r8d, DWORD PTR [rbp+56]     ; R8D = head_dim
    
    ; Compute softmax scale = 1/sqrt(head_dim)
    ; For now use a constant scale for head_dim=64 or head_dim=128
    cmp r8d, 64
    je scale_64
    cmp r8d, 128
    je scale_128
    ; Default scale for other head_dim
    vbroadcastss zmm31, DWORD PTR [softmax_scale]
    jmp scale_done
scale_64:
    vbroadcastss zmm31, DWORD PTR [scale_64_val]
    jmp scale_done
scale_128:
    vbroadcastss zmm31, DWORD PTR [scale_128_val]
scale_done:
    
    ; Call the actual tree verification kernel
    ; Parameters: RCX=Q, RDX=K, R8=V, R9=tree_mask, [RSP+40]=output, [RSP+48]=head_dim
    mov rcx, rbx
    mov rdx, r12
    mov r8, r13
    mov r9, r15
    mov QWORD PTR [rsp+40], r14     ; output
    mov DWORD PTR [rsp+48], r8d     ; head_dim
    
    ; Save registers before call
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    call TreeVerify_Batch_4x4_AVX512
    
    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    
    ; Restore stack and return
    mov rsp, rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
TreeAttention_AVX512 ENDP

; Wrapper for TreeAttention_AVX512_VerifyBatch - matches C++ signature
TreeAttention_AVX512_VerifyBatch PROC
    ; C++ signature: uint32_t TreeAttention_AVX512_VerifyBatch(
    ;     const uint32_t* draft_tokens, const uint32_t* model_tokens,
    ;     uint32_t num_tokens, uint32_t vocab_size, uint8_t* results)
    ; RCX = draft_tokens, RDX = model_tokens, R8 = num_tokens
    ; R9 = vocab_size, [RSP+40] = results
    
    ; Simple verification: compare draft vs model tokens
    xor eax, eax                    ; RAX = match count
    test r8, r8
    jz verify_done                  ; If num_tokens == 0, return 0
    
    mov r10, rcx                    ; R10 = draft_tokens
    mov r11, rdx                    ; R11 = model_tokens
    mov r12d, r8d                   ; R12 = num_tokens
    xor r13d, r13d                  ; R13 = index
    
verify_loop:
    mov ecx, DWORD PTR [r10 + r13*4]  ; ECX = draft_tokens[i]
    mov edx, DWORD PTR [r11 + r13*4]  ; EDX = model_tokens[i]
    cmp ecx, edx
    jne verify_mismatch
    inc eax                         ; Increment match count
    jmp verify_next
    
verify_mismatch:
    ; Store mismatch info in results if provided
    mov r14, QWORD PTR [rsp+40]     ; R14 = results
    test r14, r14
    jz verify_next
    mov BYTE PTR [r14 + r13], 0     ; results[i] = 0 (mismatch)
    
verify_next:
    inc r13d
    cmp r13d, r12d
    jl verify_loop
    
verify_done:
    ret
TreeAttention_AVX512_VerifyBatch ENDP

END
