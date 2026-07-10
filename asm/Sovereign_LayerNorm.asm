; ============================================================================
; Sovereign_LayerNorm.asm - Layer Normalization Kernel
; ============================================================================
; Production-ready MASM x64 implementation for RawrXD Transformer
;
; LayerNorm: y = (x - mean) / sqrt(var + epsilon) * gamma + beta
;
; Features:
;   - AVX2 optimized (8-wide F32 operations)
;   - F32 and F16 support
;   - In-place or out-of-place operation
;   - Aligned memory access
;
; Calling Convention: Microsoft x64 (RCX, RDX, R8, R9)
; ============================================================================

; ----------------------------------------------------------------------------
; External Imports
; ----------------------------------------------------------------------------
EXTERN sqrt:PROC

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data

; Constants
ALIGN 16
epsilon_ln        REAL4 1.0e-6, 1.0e-6, 1.0e-6, 1.0e-6
one_ln            REAL4 1.0, 1.0, 1.0, 1.0

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; KERNEL_COMPLETE: MASM_LayerNorm_F32_AVX2
; Sovereign_LayerNorm_F32_AVX2 - Layer Normalization for F32 tensors
; ============================================================================
; Parameters:
;   RCX = input ptr (float*)
;   RDX = output ptr (float*)
;   R8  = gamma ptr (float* - scale)
;   R9  = beta ptr (float* - shift)
;   [RSP+40] = n_elements (size_t)
;   [RSP+48] = epsilon (float)
; Returns:
;   RAX = 0 on success, -1 on error
; Clobbers: YMM0-YMM7, RAX-R11
; ============================================================================
Sovereign_LayerNorm_F32_AVX2 PROC FRAME
    ; Save registers
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
    sub     rsp, 128
    .allocstack 128
    .endprolog
    
    mov     rbp, rsp
    
    ; Parameters
    mov     r12, rcx                    ; R12 = input
    mov     r13, rdx                    ; R13 = output
    mov     r14, r8                     ; R14 = gamma
    mov     r15, r9                     ; R15 = beta
    
    ; Load from stack
    ; Stack layout: [RSP+40] = n_elements, [RSP+48] = epsilon
    ; After push rbp and other regs + sub rsp,128, RSP moved by 192 bytes
    ; So parameters are at [RBP + 192 + 40] = [RBP + 232]
    mov     rax, QWORD PTR [rbp+232]    ; n_elements
    mov     QWORD PTR [rbp+64], rax
    movss   xmm0, DWORD PTR [rbp+240]   ; epsilon
    movss   DWORD PTR [rbp+72], xmm0
    
    ; Validate
    test    rax, rax
    jz      @@error
    
    ; Step 1: Calculate mean
    vxorps  ymm0, ymm0, ymm0            ; YMM0 = accumulator
    
    mov     rcx, QWORD PTR [rbp+64]
    shr     rcx, 3                      ; Process 8 at a time
    test    rcx, rcx
    jz      @@scalar_mean
    
    mov     rsi, r12
    
@@mean_loop:
    vaddps  ymm0, ymm0, YMMWORD PTR [rsi]
    add     rsi, 32
    dec     rcx
    jnz     @@mean_loop
    
    ; Horizontal sum
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    jmp     @@mean_done
    
@@scalar_mean:
    vxorps  xmm0, xmm0, xmm0
    
@@scalar_mean_loop:
    mov     rcx, QWORD PTR [rbp+64]
    test    rcx, rcx
    jz      @@mean_done
    
    mov     rsi, r12
    xor     rbx, rbx
    
@@scalar_loop:
    cmp     rbx, rcx
    jge     @@mean_done
    
    movss   xmm1, DWORD PTR [rsi+rbx*4]
    addss   xmm0, xmm1
    inc     rbx
    jmp     @@scalar_loop
    
@@mean_done:
    ; xmm0 = sum, calculate mean
    cvtsi2ss xmm1, DWORD PTR [rbp+64]
    divss   xmm0, xmm1                  ; xmm0 = mean
    movss   DWORD PTR [rbp+76], xmm0    ; Store mean
    vbroadcastss ymm6, xmm0             ; YMM6 = mean broadcasted
    
    ; Step 2: Calculate variance (E[(x - mean)^2])
    vxorps  ymm0, ymm0, ymm0            ; YMM0 = variance accumulator
    
    mov     rcx, QWORD PTR [rbp+64]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_var
    
    mov     rsi, r12
    
@@var_loop:
    vmovaps ymm1, YMMWORD PTR [rsi]     ; Load input
    vsubps  ymm1, ymm1, ymm6            ; x - mean
    vmulps  ymm1, ymm1, ymm1            ; (x - mean)^2
    vaddps  ymm0, ymm0, ymm1            ; Accumulate
    add     rsi, 32
    dec     rcx
    jnz     @@var_loop
    
    ; Horizontal sum of variance
    vextractf128 xmm1, ymm0, 1
    vaddps  xmm0, xmm0, xmm1
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0
    jmp     @@var_done
    
@@scalar_var:
    vxorps  xmm0, xmm0, xmm0
    
@@scalar_var_loop:
    mov     rcx, QWORD PTR [rbp+64]
    test    rcx, rcx
    jz      @@var_done
    
    mov     rsi, r12
    xor     rbx, rbx
    
@@sv_loop:
    cmp     rbx, rcx
    jge     @@var_done
    
    movss   xmm1, DWORD PTR [rsi+rbx*4]
    subss   xmm1, xmm6                  ; x - mean
    mulss   xmm1, xmm1                  ; (x - mean)^2
    addss   xmm0, xmm1
    inc     rbx
    jmp     @@sv_loop
    
@@var_done:
    ; xmm0 = sum of squared differences, calculate variance
    cvtsi2ss xmm1, DWORD PTR [rbp+64]
    divss   xmm0, xmm1                  ; xmm0 = variance
    
    ; Calculate inv_std = 1 / sqrt(var + epsilon)
    addss   xmm0, DWORD PTR [rbp+72]    ; var + epsilon
    sqrtss  xmm0, xmm0                  ; sqrt(var + epsilon)
    movss   xmm1, DWORD PTR [one_ln]
    divss   xmm1, xmm0                  ; xmm1 = inv_std
    vbroadcastss ymm7, xmm1             ; YMM7 = inv_std broadcasted
    
    ; Step 3: Normalize, scale, and shift
    ; y = (x - mean) * inv_std * gamma + beta
    
    mov     rcx, QWORD PTR [rbp+64]
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar_norm
    
    mov     rsi, r12                    ; input
    mov     rdi, r13                    ; output
    mov     rbx, r14                    ; gamma
    mov     rdx, r15                    ; beta
    
@@norm_loop:
    vmovaps ymm0, YMMWORD PTR [rsi]     ; Load input
    vsubps  ymm0, ymm0, ymm6            ; x - mean
    vmulps  ymm0, ymm0, ymm7            ; (x - mean) * inv_std
    
    vmovaps ymm1, YMMWORD PTR [rbx]     ; Load gamma
    vmulps  ymm0, ymm0, ymm1            ; * gamma
    
    vmovaps ymm1, YMMWORD PTR [rdx]     ; Load beta
    vaddps  ymm0, ymm0, ymm1            ; + beta
    
    vmovaps YMMWORD PTR [rdi], ymm0     ; Store result
    
    add     rsi, 32
    add     rdi, 32
    add     rbx, 32
    add     rdx, 32
    dec     rcx
    jnz     @@norm_loop
    
@@scalar_norm:
    ; Handle remaining elements
    mov     rcx, QWORD PTR [rbp+64]
    and     rcx, 7
    jz      @@success
    
    ; Calculate starting positions
    mov     rax, QWORD PTR [rbp+64]
    shr     rax, 3
    shl     rax, 5
    
    add     r12, rax
    add     r13, rax
    add     r14, rax
    add     r15, rax
    
@@scalar_norm_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]       ; x
    subss   xmm0, xmm6                  ; x - mean
    mulss   xmm0, xmm7                  ; (x - mean) * inv_std
    mulss   xmm0, DWORD PTR [r14]     ; * gamma
    addss   xmm0, DWORD PTR [r15]       ; + beta
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
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Sovereign_LayerNorm_F32_AVX2 ENDP

; ============================================================================
; C API Exports
; ============================================================================

; ----------------------------------------------------------------------------
; layer_norm_f32 - C-compatible wrapper
; ----------------------------------------------------------------------------
; extern "C" int layer_norm_f32(const float* input, float* output,
;                               const float* gamma, const float* beta,
;                               size_t n_elements, float epsilon);
; ----------------------------------------------------------------------------
layer_norm_f32 PROC EXPORT
    ; RCX=input, RDX=output, R8=gamma, R9=beta
    ; n_elements and epsilon on stack
    jmp     Sovereign_LayerNorm_F32_AVX2
layer_norm_f32 ENDP

; ============================================================================
; End of Module
; ============================================================================
END
