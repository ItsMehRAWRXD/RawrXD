; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: MINIMAL DEBUG VERSION - Step 4
; ═══════════════════════════════════════════════════════════════════════════════
; Step 4: Add dot product computation (Q·K)
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.code

TreeAttention_Fused_VAL038 PROC FRAME
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
    sub     rsp, 256
    .allocstack 256
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = Q
    mov     r14, r8                     ; r14 = K
    mov     r15, r9                     ; r15 = V
    
    ; Load stack parameters
    mov     ebx, [rbp+72]               ; ebx = num_q
    mov     esi, [rbp+80]               ; esi = num_k
    mov     rdi, [rbp+88]               ; rdi = tree_mask
    
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
    
    ; Outer loop over queries
    xor     r8d, r8d                    ; r8d = q_idx = 0

.query_loop:
    cmp     r8d, ebx
    jae     .done
    
    ; Load Q row (head_dim = 64 = 4 zmm registers)
    mov     rax, r8
    imul    rax, 64 * 4                 ; rax = q_idx * head_dim * 4
    lea     rcx, [r13 + rax]            ; rcx = &Q[q_idx * head_dim]
    
    vmovaps zmm0, zmmword ptr [rcx]         ; Q[0:15]
    vmovaps zmm1, zmmword ptr [rcx + 64]    ; Q[16:31]
    vmovaps zmm2, zmmword ptr [rcx + 128]   ; Q[32:47]
    vmovaps zmm3, zmmword ptr [rcx + 192]   ; Q[48:63]
    
    ; Initialize accumulator for output
    vxorps  zmm4, zmm4, zmm4            ; zmm4 = accum output[0:15]
    vxorps  zmm5, zmm5, zmm5            ; zmm5 = accum output[16:31]
    vxorps  zmm6, zmm6, zmm6            ; zmm6 = accum output[32:47]
    vxorps  zmm7, zmm7, zmm7            ; zmm7 = accum output[48:63]
    
    ; Inner loop over keys
    xor     r9d, r9d                    ; r9d = k_idx = 0

.key_loop:
    cmp     r9d, esi
    jae     .store_output
    
    ; Safety guard (inner loop)
    inc     r11d
    cmp     r11d, r10d
    jae     .done
    
    ; Load K row
    mov     rax, r9
    imul    rax, 64 * 4                 ; rax = k_idx * head_dim * 4
    lea     rcx, [r14 + rax]            ; rcx = &K[k_idx * head_dim]
    
    vmovaps zmm8, zmmword ptr [rcx]         ; K[0:15]
    vmovaps zmm9, zmmword ptr [rcx + 64]      ; K[16:31]
    vmovaps zmm10, zmmword ptr [rcx + 128]    ; K[32:47]
    vmovaps zmm11, zmmword ptr [rcx + 192]    ; K[48:63]
    
    ; Compute dot product Q·K (4 FMAs per 16 elements)
    vmulps  zmm12, zmm0, zmm8           ; Q[0:15] * K[0:15]
    vfmadd231ps zmm12, zmm1, zmm9       ; += Q[16:31] * K[16:31]
    vfmadd231ps zmm12, zmm2, zmm10      ; += Q[32:47] * K[32:47]
    vfmadd231ps zmm12, zmm3, zmm11      ; += Q[48:63] * K[48:63]
    
    ; Horizontal sum to get score
    vextractf64x4 ymm8, zmm12, 1
    vaddps  ymm12, ymm12, ymm8
    vextractf128 xmm8, ymm12, 1
    vaddps  xmm12, xmm12, xmm8
    vhaddps xmm12, xmm12, xmm12
    vhaddps xmm12, xmm12, xmm12
    
    ; Broadcast score to all elements
    vbroadcastss zmm12, xmm12
    
    ; Accumulate: output += score * V (simplified - just accumulate score)
    vaddps  zmm4, zmm4, zmm12
    
    ; Next key
    inc     r9d
    jmp     .key_loop

.store_output:
    ; Store output row
    mov     rax, r8
    imul    rax, 64 * 4                 ; rax = q_idx * head_dim * 4
    lea     rcx, [r12 + rax]            ; rcx = &output[q_idx * head_dim]
    
    vmovaps zmmword ptr [rcx], zmm4
    vmovaps zmmword ptr [rcx + 64], zmm5
    vmovaps zmmword ptr [rcx + 128], zmm6
    vmovaps zmmword ptr [rcx + 192], zmm7
    
    ; Next query
    inc     r8d
    jmp     .query_loop

.done:
    ; Epilogue
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
