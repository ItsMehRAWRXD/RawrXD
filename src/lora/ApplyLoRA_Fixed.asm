; LoRA Optimized Kernel - Phase 20 (Fixed)
; ApplyLoRA_Fixed.asm
; ============================================================================
; High-performance LoRA inference kernel
; Target: < 10ms for rank=8, hidden_dim=768
; ============================================================================

; LoRAContext structure offsets (64-byte aligned)
CTX_MAGIC       EQU 0
CTX_RANK        EQU 8
CTX_HIDDEN_DIM  EQU 12
CTX_INPUT_DIM   EQU 16
CTX_RESERVED    EQU 20
CTX_PTR_A       EQU 24
CTX_PTR_B       EQU 32
CTX_ALPHA       EQU 40
CTX_SCALE       EQU 44
CTX_STATUS      EQU 48

.code

; ============================================================================
; Function: ApplyLoRA_Optimized
; Purpose: Optimized LoRA application
; Input:  RCX = base_output pointer
;         RDX = input pointer
;         R8  = result pointer
;         R9  = context pointer
;         R10 = token_count
; Output: 0 on success
; ============================================================================
ApplyLoRA_Optimized PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
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
    
    ; Save input parameters
    mov     r15, rcx            ; r15 = base_output
    mov     r14, rdx            ; r14 = input
    mov     r13, r8             ; r13 = result
    mov     r12, r9             ; r12 = context
    
    ; Load context parameters
    mov     ebx, dword ptr [r12 + CTX_RANK]        ; ebx = rank
    mov     r11d, dword ptr [r12 + CTX_HIDDEN_DIM] ; r11d = hidden_dim
    
    ; Load matrix pointers
    mov     r9, qword ptr [r12 + CTX_PTR_A]        ; r9 = matrix_A
    mov     r8, qword ptr [r12 + CTX_PTR_B]        ; r8 = matrix_B
    
    ; Load scale factor
    vbroadcastss ymm15, dword ptr [r12 + CTX_SCALE]
    
    ; Copy base_output to result
    mov     rsi, r15
    mov     rdi, r13
    mov     ecx, r11d
    rep movsd
    
    ; Main computation: for each output row
    xor     r10d, r10d          ; r10d = row index
    
row_loop:
    cmp     r10d, r11d
    jge     done
    
    ; Compute temp = A[row] dot input
    ; Initialize accumulator
    vxorps  xmm0, xmm0, xmm0
    
    ; Inner loop: dot product of A[row] and input
    xor     ecx, ecx            ; ecx = rank index
    
dot_loop:
    cmp     ecx, ebx
    jge     dot_done
    
    ; Load A[row][ecx] and input[ecx]
    mov     eax, r10d
    imul    eax, ebx
    add     eax, ecx
    movss   xmm1, dword ptr [r9 + rax*4]      ; A[row][ecx]
    movss   xmm2, dword ptr [r14 + rcx*4]   ; input[ecx]
    mulss   xmm1, xmm2
    addss   xmm0, xmm1
    
    inc     ecx
    jmp     dot_loop
    
dot_done:
    ; xmm0 = temp = A[row] dot input
    
    ; Now compute: result[row] += scale * (B[row] dot temp)
    ; For each element in B[row]
    xor     ecx, ecx            ; ecx = col index
    
b_loop:
    cmp     ecx, ebx
    jge     row_done
    
    ; Compute: result[row] += scale * B[row][ecx] * temp
    mov     eax, r10d
    imul    eax, ebx
    add     eax, ecx
    movss   xmm1, dword ptr [r8 + rax*4]      ; B[row][ecx]
    mulss   xmm1, xmm0                        ; B[row][ecx] * temp
    mulss   xmm1, xmm15                       ; * scale
    
    ; Add to result[row]
    movss   xmm2, dword ptr [r13 + r10*4]     ; result[row]
    addss   xmm2, xmm1
    movss   dword ptr [r13 + r10*4], xmm2
    
    inc     ecx
    jmp     b_loop
    
row_done:
    inc     r10d
    jmp     row_loop
    
done:
    vzeroupper
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    xor     rax, rax
    ret
ApplyLoRA_Optimized ENDP

END
