; ============================================================================
; Sovereign_LayerNorm_Fixed.asm - Simplified Layer Normalization Kernel
; ============================================================================
; Fixed version with simpler control flow
; ============================================================================

; ----------------------------------------------------------------------------
; External Imports
; ----------------------------------------------------------------------------
EXTERN sqrtf:PROC

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data

ALIGN 16
ln_epsilon      REAL4 1.0e-6, 1.0e-6, 1.0e-6, 1.0e-6
ln_one          REAL4 1.0, 1.0, 1.0, 1.0

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; KERNEL_COMPLETE: MASM_LayerNorm_F32_AVX2_Fixed
; ============================================================================
; Parameters (Microsoft x64):
;   RCX = input ptr
;   RDX = output ptr
;   R8  = gamma ptr
;   R9  = beta ptr
;   [RSP+40] = n_elements
;   [RSP+48] = epsilon
; Returns: RAX = 0 on success
; ============================================================================
Sovereign_LayerNorm_F32_AVX2 PROC FRAME
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
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    mov     rbp, rsp
    
    ; Save parameters
    mov     r12, rcx                    ; input
    mov     r13, rdx                    ; output
    mov     r14, r8                     ; gamma
    mov     r15, r9                     ; beta
    
    ; Load stack parameters
    ; After 6 pushes (48 bytes) + sub rsp,64, RSP moved 112 bytes
    ; Original params at [RSP+40] and [RSP+48] are now at [RBP+152] and [RBP+160]
    mov     rax, QWORD PTR [rbp+152]    ; n_elements (112 + 40)
    mov     QWORD PTR [rbp+32], rax      ; save n_elements
    movss   xmm0, DWORD PTR [rbp+160]   ; epsilon (112 + 48)
    movss   DWORD PTR [rbp+40], xmm0    ; save epsilon
    
    ; Validate
    test    rax, rax
    jz      @@error
    
    ; Calculate mean using AVX2
    vxorps  ymm0, ymm0, ymm0            ; accumulator
    mov     rcx, [rbp+32]
    shr     rcx, 3                      ; n / 8
    test    rcx, rcx
    jz      @@scalar_mean
    
    mov     rsi, r12
    mov     rbx, rcx
    
@@mean_loop:
    vaddps  ymm0, ymm0, [rsi]
    add     rsi, 32
    dec     rbx
    jnz     @@mean_loop
    
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
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
    movss   DWORD PTR [rbp+44], xmm0    ; save mean
    vbroadcastss ymm6, xmm0             ; ymm6 = mean
    
    ; Calculate variance
    vxorps  ymm0, ymm0, ymm0
    mov     rcx, [rbp+32]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_var
    
    mov     rsi, r12
    mov     rbx, rcx
    
@@var_loop:
    vmovaps ymm1, [rsi]
    vsubps  ymm1, ymm1, ymm6
    vmulps  ymm1, ymm1, ymm1
    vaddps  ymm0, ymm0, ymm1
    add     rsi, 32
    dec     rbx
    jnz     @@var_loop
    
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
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
    addss   xmm0, DWORD PTR [rbp+40]     ; + epsilon
    sqrtss  xmm0, xmm0                  ; std dev
    movss   xmm1, DWORD PTR [ln_one]
    divss   xmm1, xmm0                  ; 1/std = inv_std
    vbroadcastss ymm7, xmm1             ; ymm7 = inv_std
    
    ; Normalize, scale, shift
    mov     rcx, [rbp+32]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_norm
    
    mov     rsi, r12
    mov     rdi, r13
    mov     rbx, r14
    mov     rdx, r15
    
@@norm_loop:
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
    jnz     @@norm_loop
    
@@scalar_norm:
    ; Handle remaining elements
    mov     rcx, [rbp+32]
    and     rcx, 7
    jz      @@success
    
    mov     rax, [rbp+32]
    shr     rax, 3
    shl     rax, 5
    add     r12, rax
    add     r13, rax
    add     r14, rax
    add     r15, rax
    
@@scalar_norm_loop:
    test    rcx, rcx
    jz      @@success
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
    
@@success:
    vzeroupper
    xor     rax, rax
    jmp     @@cleanup
    
@@error:
    mov     rax, -1
    
@@cleanup:
    add     rsp, 64
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Sovereign_LayerNorm_F32_AVX2 ENDP

; C API wrapper
layer_norm_f32 PROC EXPORT
    jmp     Sovereign_LayerNorm_F32_AVX2
layer_norm_f32 ENDP

END
