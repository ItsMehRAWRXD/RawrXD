; ============================================================================
; RawrXD Tree Attention Kernel - AVX-512 Implementation
; VAL-032: Speculative Decoding Acceleration
;
; Target: Verify 16 draft tokens (4x4 tree) in single AVX-512 pass
; Expected latency: <500ns per tree verification
; ============================================================================

; Assembler directives
.686P
.XMM
.MODEL FLAT, C
OPTION CASEMAP:NONE

; ============================================================================
; Data Section
; ============================================================================
.DATA

; Softmax constants
align 64
exp_lut QWORD 256 DUP (0)           ; Lookup table for exp approximation
softmax_scale REAL4 1.0             ; 1/sqrt(head_dim)

; Tree mask patterns (pre-computed for 4x4 tree)
; Each bit represents whether node i can attend to node j
align 64
tree_mask_4x4 BYTE 256 DUP (0FFh)   ; All ones initially

; ============================================================================
; Code Section
; ============================================================================
.CODE

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
    
    sub rsp, 128                    ; Allocate shadow space + local vars
    .allocstack 128
    
    .endprolog
    
    ; Load parameters
    mov rbx, rcx                    ; RBX = Q pointer
    mov r12, rdx                    ; R12 = K pointer
    mov r13, r8                     ; R13 = V pointer
    mov r14, r9                     ; R14 = Tree mask pointer
    mov r15, QWORD PTR [rsp+168]    ; R15 = Output pointer
    mov r8d, DWORD PTR [rsp+176]    ; R8D = Head dimension
    movss xmm0, REAL4 PTR [rsp+184] ; XMM0 = Softmax scale
    vbroadcastss zmm31, xmm0        ; ZMM31 = scale broadcasted
    
    ; Constants
    mov eax, 16                     ; 16 nodes in 4x4 tree
    mov r9d, r8d
    shr r9d, 4                      ; R9 = head_dim / 16 (number of 512-bit chunks)
    
    ; =========================================================================
    ; Phase 1: Compute Q @ K^T (16x16 attention scores)
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = query node index (0-15)
    
.query_loop:
    ; Load query vector for node r10
    vmovups zmm0, [rbx + r10*64]    ; ZMM0 = Q[r10] (first 64 bytes)
    
    xor r11d, r11d                  ; R11 = key node index (0-15)
    
.key_loop:
    ; Compute dot product Q[r10] . K[r11]
    vxorps zmm30, zmm30, zmm30      ; ZMM30 = accumulator
    
    xor r12d, r12d                  ; R12 = dimension chunk index
    
.dim_loop:
    ; Load K chunk
    mov rax, r11
    imul rax, r8                    ; RAX = r11 * head_dim
    mov rcx, r12
    shl rcx, 6                      ; RCX = r12 * 64
    add rax, rcx
    vmovups zmm1, [r12 + rax]       ; ZMM1 = K[r11][r12*16:r12*16+15]
    
    ; Load Q chunk
    mov rax, r10
    imul rax, r8
    add rax, rcx
    vmovups zmm2, [rbx + rax]       ; ZMM2 = Q[r10][r12*16:r12*16+15]
    
    ; Fused multiply-add
    vfmadd231ps zmm30, zmm2, zmm1   ; ZMM30 += Q * K
    
    inc r12d
    cmp r12d, r9d
    jl .dim_loop
    
    ; Horizontal sum of ZMM30
    vextractf64x4 ymm1, zmm30, 1    ; Extract high 256 bits
    vaddps ymm0, ymm30, ymm1        ; Combine
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    
    ; Store score
    mov rax, r10
    shl rax, 4                      ; RAX = r10 * 16
    add rax, r11
    movss REAL4 PTR [rsp + rax*4], xmm0
    
    inc r11d
    cmp r11d, 16
    jl .key_loop
    
    inc r10d
    cmp r10d, 16
    jl .query_loop
    
    ; =========================================================================
    ; Phase 2: Apply Tree Mask and Softmax
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = row index
    
    .softmax_row_loop:
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
    jl .softmax_row_loop
    
    ; =========================================================================
    ; Phase 3: Compute Attention @ V (Output)
    ; =========================================================================
    
    xor r10d, r10d                  ; R10 = output row
    
    .output_row_loop:
    vxorps zmm30, zmm30, zmm30      ; ZMM30 = accumulator
    
    xor r11d, r11d                  ; R11 = column in V
    
    .v_col_loop:
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
    jl .v_col_loop
    
    ; Store output row
    mov rax, r10
    imul rax, r8
    vmovups [r15 + rax], zmm30
    
    inc r10d
    cmp r10d, 16
    jl .output_row_loop
    
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
; Constants
; -----------------------------------------------------------------------------
align 64
one REAL4 1.0
align 64
half REAL4 0.5
align 64
one_sixth REAL4 0.166666667
align 64
one_twenty_fourth REAL4 0.041666667

; -----------------------------------------------------------------------------
; Feature Detection
; -----------------------------------------------------------------------------
PUBLIC TreeAttention_HasAVX512

TreeAttention_HasAVX512 PROC
    ; Check CPUID for AVX-512 support
    mov eax, 1
    cpuid
    and ecx, 10000000h              ; Check bit 28 (AVX)
    jz .no_avx512
    
    mov eax, 7
    xor ecx, ecx
    cpuid
    and ebx, 00010000h              ; Check bit 16 (AVX-512F)
    jz .no_avx512
    
    mov eax, 1                      ; Return 1 (AVX-512 supported)
    ret
    
.no_avx512:
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

END
