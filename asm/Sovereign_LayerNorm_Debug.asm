; ============================================================================
; Sovereign_LayerNorm_Debug.asm - Debug Layer Normalization
; ============================================================================
; Step by step implementation to find the hang
; ============================================================================

.data
ALIGN 16
ln_epsilon REAL4 1.0e-6, 1.0e-6, 1.0e-6, 1.0e-6
ln_one     REAL4 1.0, 1.0, 1.0, 1.0

.code

; Public exports for kernel functions
PUBLIC Sovereign_LayerNorm_F32_AVX2
PUBLIC layer_norm_f32

; ============================================================================
; layer_norm_f32 - C API
; RCX=input, RDX=output, R8=gamma, R9=beta, [RSP+40]=n_elements, [RSP+48]=epsilon
; Returns: RAX=0 on success
; ============================================================================
layer_norm_f32 PROC EXPORT FRAME
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
    sub     rsp, 48
    .allocstack 48
    .endprolog
    
    mov     rbp, rsp
    
    ; Save parameters
    mov     r12, rcx                    ; input
    mov     r13, rdx                    ; output
    mov     r14, r8                     ; gamma
    mov     r15, r9                     ; beta
    
    ; Load n_elements from stack
    ; After 6 pushes (48 bytes) + sub rsp,48 = 96 bytes
    ; Original [RSP+40] is now at [RBP+96+40] = [RBP+136]
    mov     rax, QWORD PTR [rbp+136]      ; n_elements
    mov     QWORD PTR [rbp+32], rax       ; save n_elements at [rbp+32]
    
    ; Validate
    test    rax, rax
    jz      @@error
    
    ; Step 1: Calculate mean using AVX2
    vxorps  ymm0, ymm0, ymm0            ; accumulator
    mov     rcx, QWORD PTR [rbp+32]
    shr     rcx, 3                      ; n / 8
    test    rcx, rcx
    jz      @@scalar_mean
    
    mov     rsi, r12
    
@@mean_loop:
    vaddps  ymm0, ymm0, YMMWORD PTR [rsi]
    add     rsi, 32
    dec     rcx
    jnz     @@mean_loop
    
    ; Horizontal sum using simpler method
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    ; xmm0 now has 4 floats, need to sum them
    vmovhlps xmm1, xmm1, xmm0           ; move high 2 to xmm1
    vaddps  xmm0, xmm0, xmm1            ; add them
    vshufps xmm1, xmm0, xmm0, 1         ; get second element
    vaddss  xmm0, xmm0, xmm1            ; add to first
    jmp     @@mean_done
    
@@scalar_mean:
    xorps   xmm0, xmm0
    mov     rcx, QWORD PTR [rbp+32]
    mov     rsi, r12
    xor     rbx, rbx
    
@@scalar_mean_loop:
    cmp     rbx, rcx
    jge     @@mean_done
    addss   xmm0, DWORD PTR [rsi+rbx*4]
    inc     rbx
    jmp     @@scalar_mean_loop
    
@@mean_done:
    ; xmm0 = sum, divide by n to get mean
    cvtsi2ss xmm1, DWORD PTR [rbp+32]
    divss   xmm0, xmm1
    movss   DWORD PTR [rbp+40], xmm0    ; save mean
    vbroadcastss ymm6, xmm0             ; ymm6 = mean
    
    ; Step 2: Calculate variance
    vxorps  ymm0, ymm0, ymm0
    mov     rcx, QWORD PTR [rbp+32]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_var
    
    mov     rsi, r12
    
@@var_loop:
    vmovaps ymm1, YMMWORD PTR [rsi]
    vsubps  ymm1, ymm1, ymm6
    vmulps  ymm1, ymm1, ymm1
    vaddps  ymm0, ymm0, ymm1
    add     rsi, 32
    dec     rcx
    jnz     @@var_loop
    
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm1, xmm0
    vaddps  xmm0, xmm0, xmm1
    vshufps xmm1, xmm0, xmm0, 1
    vaddss  xmm0, xmm0, xmm1
    jmp     @@var_done
    
@@scalar_var:
    xorps   xmm0, xmm0
    mov     rcx, QWORD PTR [rbp+32]
    mov     rsi, r12
    xor     rbx, rbx
    
@@scalar_var_loop:
    cmp     rbx, rcx
    jge     @@var_done
    movss   xmm1, DWORD PTR [rsi+rbx*4]
    subss   xmm1, xmm6
    mulss   xmm1, xmm1
    addss   xmm0, xmm1
    inc     rbx
    jmp     @@scalar_var_loop
    
@@var_done:
    ; xmm0 = sum of squared diffs, divide by n
    cvtsi2ss xmm1, DWORD PTR [rbp+32]
    divss   xmm0, xmm1                  ; variance
    addss   xmm0, DWORD PTR [ln_epsilon] ; + epsilon
    sqrtss  xmm0, xmm0                  ; std dev
    movss   xmm1, DWORD PTR [ln_one]
    divss   xmm1, xmm0                  ; 1/std = inv_std
    vbroadcastss ymm7, xmm1             ; ymm7 = inv_std
    
    ; Step 3: Normalize, scale, shift
    mov     rcx, QWORD PTR [rbp+32]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_norm
    
    mov     rsi, r12                    ; input
    mov     rdi, r13                    ; output
    mov     rbx, r14                    ; gamma
    mov     rdx, r15                    ; beta
    
@@norm_loop:
    cmp     rcx, 0
    jle     @@scalar_norm
    vmovaps ymm0, YMMWORD PTR [rsi]
    vsubps  ymm0, ymm0, ymm6
    vmulps  ymm0, ymm0, ymm7
    vmulps  ymm0, ymm0, YMMWORD PTR [rbx]
    vaddps  ymm0, ymm0, YMMWORD PTR [rdx]
    vmovaps YMMWORD PTR [rdi], ymm0
    add     rsi, 32
    add     rdi, 32
    add     rbx, 32
    add     rdx, 32
    dec     rcx
    jmp     @@norm_loop
    
@@scalar_norm:
    ; Handle remaining elements
    mov     rcx, QWORD PTR [rbp+32]
    and     rcx, 7
    jz      @@done
    
    mov     rax, QWORD PTR [rbp+32]
    shr     rax, 3
    shl     rax, 5
    add     r12, rax
    add     r13, rax
    add     r14, rax
    add     r15, rax
    
@@scalar_norm_loop:
    test    rcx, rcx
    jz      @@done
    movss   xmm0, DWORD PTR [r12]
    subss   xmm0, xmm6
    mulss   xmm0, xmm7
    mulss   xmm0, DWORD PTR [r14]
    addss   xmm0, DWORD PTR [r15]
    movss   DWORD PTR [r13], xmm0
    add     r12, 4
    add     r13, 4
    add     r14, 4
    add     r15, 4
    dec     rcx
    jmp     @@scalar_norm_loop
    
@@done:
    vzeroupper
    xor     rax, rax
    jmp     @@cleanup
    
@@error:
    mov     rax, -1
    
@@cleanup:
    add     rsp, 48
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
layer_norm_f32 ENDP

; Also export the internal name
Sovereign_LayerNorm_F32_AVX2 PROC EXPORT
    jmp     layer_norm_f32
Sovereign_LayerNorm_F32_AVX2 ENDP

END
