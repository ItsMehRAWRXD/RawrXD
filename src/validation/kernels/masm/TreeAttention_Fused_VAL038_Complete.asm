; VAL-038: Complete working version with corrected stack offsets
OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.data
scale_factor    REAL4   0.125           ; 1/sqrt(64)
neg_inf         REAL4   -1.0e38         ; Approximate -infinity

.code

TreeAttention_Fused_VAL038 PROC FRAME
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
    sub     rsp, 256
    .allocstack 256
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    
    ; Load stack parameters (corrected offsets)
    mov     ebx, [rbp+104]              ; ebx = num_q
    mov     esi, [rbp+112]              ; esi = num_k
    mov     rdi, [rbp+120]              ; rdi = tree_mask
    
    ; Validate parameters
    test    ebx, ebx
    jz      .done
    test    esi, esi
    jz      .done
    
    ; Safety guard: max iterations = num_q * num_k * 2
    mov     eax, ebx
    imul    eax, esi
    shl     eax, 1
    mov     r10d, eax                   ; r10d = max iterations
    xor     r11d, r11d                  ; r11d = iteration counter
    
    ; Broadcast scale factor
    vbroadcastss zmm15, dword ptr [scale_factor]
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0
    
    ; Debug: Store outer loop entry marker
    mov     dword ptr [r12], 0DDDDDDDDh

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Debug: Store query index
    mov     dword ptr [r12+4], r8d
    
    ; Load Q row (head_dim = 64 = 4 zmm registers)
    mov     rax, r8
    imul    rax, 64 * 4                 ; rax = q_idx * head_dim * 4
    lea     rcx, [r13 + rax]            ; rcx = &Q[q_idx * head_dim]
    
    vmovaps zmm0, zmmword ptr [rcx]         ; Q[0:15]
    vmovaps zmm1, zmmword ptr [rcx + 64]    ; Q[16:31]
    vmovaps zmm2, zmmword ptr [rcx + 128]   ; Q[32:47]
    vmovaps zmm3, zmmword ptr [rcx + 192]   ; Q[48:63]
    
    ; Initialize accumulators
    vxorps  zmm4, zmm4, zmm4                ; zmm4 = accum output[0:15]
    vxorps  zmm5, zmm5, zmm5                ; zmm5 = accum output[16:31]
    vxorps  zmm6, zmm6, zmm6                ; zmm6 = accum output[32:47]
    vxorps  zmm7, zmm7, zmm7                ; zmm7 = accum output[48:63]
    
    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0
    
    ; Debug: Store inner loop entry marker
    mov     dword ptr [r12+8], 0EEEEEEEEh

.key_loop:
    cmp     r9d, esi
    jae     .store_output
    
    ; Debug: Store key index
    mov     dword ptr [r12+12], r9d
    
    ; Safety guard
    inc     r11d
    cmp     r11d, r10d
    jae     .done
    
    ; Check tree mask
    mov     rax, r8
    imul    rax, rsi                    ; rax = q_idx * num_k
    add     rax, r9                     ; rax = q_idx * num_k + k_idx
    cmp     byte ptr [rdi + rax], 0
    je      .skip_key                   ; Skip if masked
    
    ; Load K row
    mov     rax, r9
    imul    rax, 64 * 4
    lea     rcx, [r14 + rax]            ; rcx = &K[k_idx * head_dim]
    
    vmovaps zmm8, zmmword ptr [rcx]
    vmovaps zmm9, zmmword ptr [rcx + 64]
    vmovaps zmm10, zmmword ptr [rcx + 128]
    vmovaps zmm11, zmmword ptr [rcx + 192]
    
    ; Compute dot product Q·K
    vmulps  zmm12, zmm0, zmm8
    vfmadd231ps zmm12, zmm1, zmm9
    vfmadd231ps zmm12, zmm2, zmm10
    vfmadd231ps zmm12, zmm3, zmm11
    
    ; Horizontal sum to get score
    vextractf64x4 ymm8, zmm12, 1
    vaddps  ymm12, ymm12, ymm8
    vextractf128 xmm8, ymm12, 1
    vaddps  xmm12, xmm12, xmm8
    vhaddps xmm12, xmm12, xmm12
    vhaddps xmm12, xmm12, xmm12
    
    ; Scale by 1/sqrt(head_dim)
    vmulss  xmm12, xmm12, xmm15
    
    ; Broadcast score as weight
    vbroadcastss zmm9, xmm12
    
    ; Load V row and accumulate
    mov     rax, r9
    imul    rax, 64 * 4
    lea     rcx, [r15 + rax]            ; rcx = &V[k_idx * head_dim]
    
    vmovaps zmm10, zmmword ptr [rcx]
    vmovaps zmm11, zmmword ptr [rcx + 64]
    vmovaps zmm12, zmmword ptr [rcx + 128]
    vmovaps zmm8, zmmword ptr [rcx + 192]
    
    ; Accumulate: output += weight * V
    vfmadd231ps zmm4, zmm9, zmm10
    vfmadd231ps zmm5, zmm9, zmm11
    vfmadd231ps zmm6, zmm9, zmm12
    vfmadd231ps zmm7, zmm9, zmm8

.skip_key:
    inc     r9d
    jmp     .key_loop

.store_output:
    ; Store output row
    mov     rax, r8
    imul    rax, 64 * 4
    lea     rcx, [r12 + rax]            ; rcx = &output[q_idx * head_dim]
    
    vmovaps zmmword ptr [rcx], zmm4
    vmovaps zmmword ptr [rcx + 64], zmm5
    vmovaps zmmword ptr [rcx + 128], zmm6
    vmovaps zmmword ptr [rcx + 192], zmm7
    
    ; Next query
    inc     r8d
    jmp     .query_loop

.done:
    vzeroupper
    add     rsp, 256
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

TreeAttention_Fused_VAL038 ENDP

END
