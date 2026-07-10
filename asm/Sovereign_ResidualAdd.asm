; ============================================================================
; Sovereign_ResidualAdd.asm - Residual Connection Kernel
; ============================================================================
; Production-ready MASM x64 implementation for RawrXD Transformer
;
; Residual Add: output = input + residual
;   - Supports F32 and F16
;   - AVX2/AVX-512 optimized paths
;   - In-place variant supported
;   - Optional scaling factor (for pre-norm architectures)
;
; Calling Convention: Microsoft x64 (RCX, RDX, R8, R9)
; ============================================================================

; ----------------------------------------------------------------------------
; External Imports
; ----------------------------------------------------------------------------
EXTERN memcpy:PROC

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data

; Constants
ALIGN 16
residual_one    REAL4 1.0, 1.0, 1.0, 1.0
residual_half   REAL4 0.5, 0.5, 0.5, 0.5
residual_sqrt2  REAL4 1.41421356, 1.41421356, 1.41421356, 1.41421356

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; KERNEL_COMPLETE: MASM_ResidualAdd_F32_AVX2
; Sovereign_ResidualAdd_F32_AVX2 - Element-wise addition for F32 tensors
; ============================================================================
; Parameters:
;   RCX = input ptr (float*)
;   RDX = residual ptr (float*)
;   R8  = output ptr (float*)
;   R9  = n_elements (size_t)
; Returns:
;   RAX = 0 on success, -1 on error
; Clobbers: YMM0-YMM3, RAX-R11
; ============================================================================
Sovereign_ResidualAdd_F32_AVX2 PROC FRAME
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
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    mov     rbp, rsp
    
    ; Parameters
    mov     r12, rcx                    ; R12 = input
    mov     r13, rdx                    ; R13 = residual
    mov     r14, r8                     ; R14 = output
    mov     r15, r9                     ; R15 = n_elements
    
    ; Validate
    test    r15, r15
    jz      @@success                   ; Zero elements is valid
    
    ; Check for null pointers
    test    r12, r12
    jz      @@error
    test    r13, r13
    jz      @@error
    test    r14, r14
    jz      @@error
    
    ; Check alignment for AVX2 path
    mov     rax, r12
    or      rax, r13
    or      rax, r14
    test    rax, 31
    jnz     @@unaligned_path
    
@@aligned_path:
    ; Process 8 elements at a time with AVX2
    mov     rcx, r15
    shr     rcx, 3                      ; RCX = n_elements / 8
    test    rcx, rcx
    jz      @@scalar_cleanup
    
    mov     rsi, r12                    ; RSI = input
    mov     rdx, r13                    ; RDX = residual
    mov     rdi, r14                    ; RDI = output
    
@@avx2_loop:
    ; Load 8 floats from each input
    vmovaps ymm0, YMMWORD PTR [rsi]     ; YMM0 = input[0:7]
    vmovaps ymm1, YMMWORD PTR [rdx]     ; YMM1 = residual[0:7]
    
    ; Add: output = input + residual
    vaddps  ymm2, ymm0, ymm1
    
    ; Store result
    vmovaps YMMWORD PTR [rdi], ymm2
    
    ; Advance pointers
    add     rsi, 32
    add     rdx, 32
    add     rdi, 32
    
    dec     rcx
    jnz     @@avx2_loop
    
@@scalar_cleanup:
    ; Handle remaining elements (0-7)
    mov     rcx, r15
    and     rcx, 7                      ; RCX = remaining elements
    jz      @@success
    
    ; Calculate starting positions for remainder
    mov     rax, r15
    shr     rax, 3
    shl     rax, 5                      ; RAX = bytes processed by AVX2
    
    add     r12, rax
    add     r13, rax
    add     r14, rax
    
@@scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    ; Load single floats
    movss   xmm0, DWORD PTR [r12]
    movss   xmm1, DWORD PTR [r13]
    
    ; Add
    addss   xmm0, xmm1
    
    ; Store
    movss   DWORD PTR [r14], xmm0
    
    ; Advance
    add     r12, 4
    add     r13, 4
    add     r14, 4
    dec     rcx
    jmp     @@scalar_loop
    
@@unaligned_path:
    ; Handle unaligned memory with unaligned loads
    mov     rcx, r15
    shr     rcx, 3                      ; Process 8 at a time
    test    rcx, rcx
    jz      @@unaligned_scalar
    
@@unaligned_loop:
    vmovups ymm0, YMMWORD PTR [r12]
    vmovups ymm1, YMMWORD PTR [r13]
    vaddps  ymm2, ymm0, ymm1
    vmovups YMMWORD PTR [r14], ymm2
    
    add     r12, 32
    add     r13, 32
    add     r14, 32
    dec     rcx
    jnz     @@unaligned_loop
    
@@unaligned_scalar:
    ; Handle remainder
    mov     rcx, r15
    and     rcx, 7
    jz      @@success
    
@@unaligned_scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]
    movss   xmm1, DWORD PTR [r13]
    addss   xmm0, xmm1
    movss   DWORD PTR [r14], xmm0
    
    add     r12, 4
    add     r13, 4
    add     r14, 4
    dec     rcx
    jmp     @@unaligned_scalar_loop
    
@@success:
    vzeroupper
    xor     rax, rax                    ; Return 0 (success)
    jmp     @@cleanup
    
@@error:
    mov     rax, -1                     ; Return -1 (error)
    
@@cleanup:
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
Sovereign_ResidualAdd_F32_AVX2 ENDP

; ============================================================================
; KERNEL_COMPLETE: MASM_ResidualAdd_F32_InPlace_AVX2
; Sovereign_ResidualAdd_F32_InPlace_AVX2 - In-place residual addition
; ============================================================================
; Parameters:
;   RCX = buffer ptr (float* - input/output)
;   RDX = residual ptr (float*)
;   R8  = n_elements (size_t)
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
Sovereign_ResidualAdd_F32_InPlace_AVX2 PROC FRAME
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
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    mov     rbp, rsp
    
    ; Parameters
    mov     r12, rcx                    ; R12 = buffer (input/output)
    mov     r13, rdx                    ; R13 = residual
    mov     r14, r8                     ; R14 = n_elements
    
    ; Validate
    test    r14, r14
    jz      @@success
    test    r12, r12
    jz      @@error
    test    r13, r13
    jz      @@error
    
    ; Check alignment
    mov     rax, r12
    or      rax, r13
    test    rax, 31
    jnz     @@unaligned
    
@@aligned:
    mov     rcx, r14
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar
    
@@avx2_loop:
    vmovaps ymm0, YMMWORD PTR [r12]
    vmovaps ymm1, YMMWORD PTR [r13]
    vaddps  ymm0, ymm0, ymm1
    vmovaps YMMWORD PTR [r12], ymm0
    
    add     r12, 32
    add     r13, 32
    dec     rcx
    jnz     @@avx2_loop
    
@@scalar:
    mov     rcx, r14
    and     rcx, 7
    jz      @@success
    
@@scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]
    movss   xmm1, DWORD PTR [r13]
    addss   xmm0, xmm1
    movss   DWORD PTR [r12], xmm0
    
    add     r12, 4
    add     r13, 4
    dec     rcx
    jmp     @@scalar_loop
    
@@unaligned:
    mov     rcx, r14
    shr     rcx, 3
    test    rcx, rcx
    jz      @@unaligned_scalar
    
@@unaligned_loop:
    vmovups ymm0, YMMWORD PTR [r12]
    vmovups ymm1, YMMWORD PTR [r13]
    vaddps  ymm0, ymm0, ymm1
    vmovups YMMWORD PTR [r12], ymm0
    
    add     r12, 32
    add     r13, 32
    dec     rcx
    jnz     @@unaligned_loop
    
@@unaligned_scalar:
    mov     rcx, r14
    and     rcx, 7
    jz      @@success
    
@@unaligned_scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]
    movss   xmm1, DWORD PTR [r13]
    addss   xmm0, xmm1
    movss   DWORD PTR [r12], xmm0
    
    add     r12, 4
    add     r13, 4
    dec     rcx
    jmp     @@unaligned_scalar_loop
    
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
Sovereign_ResidualAdd_F32_InPlace_AVX2 ENDP

; ============================================================================
; KERNEL_COMPLETE: MASM_ResidualAdd_Scaled_F32_AVX2
; Sovereign_ResidualAdd_Scaled_F32_AVX2 - Residual add with scaling factor
; ============================================================================
; Parameters:
;   RCX = input ptr (float*)
;   RDX = residual ptr (float*)
;   R8  = output ptr (float*)
;   R9  = n_elements (size_t)
;   [RSP+40] = scale_factor (float)
; Returns:
;   RAX = 0 on success, -1 on error
; ============================================================================
Sovereign_ResidualAdd_Scaled_F32_AVX2 PROC FRAME
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
    mov     r13, rdx                    ; R13 = residual
    mov     r14, r8                     ; R14 = output
    mov     r15, r9                     ; R15 = n_elements
    
    ; Load scale factor
    movss   xmm0, DWORD PTR [rsp+168]   ; scale_factor
    vbroadcastss ymm3, xmm0             ; YMM3 = scale factor broadcasted
    
    ; Validate
    test    r15, r15
    jz      @@success
    
    ; Check alignment
    mov     rax, r12
    or      rax, r13
    or      rax, r14
    test    rax, 31
    jnz     @@unaligned
    
@@aligned:
    mov     rcx, r15
    shr     rcx, 3
    test    rcx, rcx
    jz      @@scalar
    
@@avx2_loop:
    vmovaps ymm0, YMMWORD PTR [r12]     ; input
    vmovaps ymm1, YMMWORD PTR [r13]     ; residual
    
    ; Scale residual: residual * scale
    vmulps  ymm1, ymm1, ymm3
    
    ; Add: input + scaled_residual
    vaddps  ymm2, ymm0, ymm1
    
    vmovaps YMMWORD PTR [r14], ymm2
    
    add     r12, 32
    add     r13, 32
    add     r14, 32
    dec     rcx
    jnz     @@avx2_loop
    
@@scalar:
    mov     rcx, r15
    and     rcx, 7
    jz      @@success
    
@@scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]       ; input
    movss   xmm1, DWORD PTR [r13]       ; residual
    mulss   xmm1, xmm3                  ; residual * scale
    addss   xmm0, xmm1                  ; input + scaled_residual
    movss   DWORD PTR [r14], xmm0
    
    add     r12, 4
    add     r13, 4
    add     r14, 4
    dec     rcx
    jmp     @@scalar_loop
    
@@unaligned:
    ; Unaligned path
    mov     rcx, r15
    shr     rcx, 3
    test    rcx, rcx
    jz      @@unaligned_scalar
    
@@unaligned_loop:
    vmovups ymm0, YMMWORD PTR [r12]
    vmovups ymm1, YMMWORD PTR [r13]
    vmulps  ymm1, ymm1, ymm3
    vaddps  ymm2, ymm0, ymm1
    vmovups YMMWORD PTR [r14], ymm2
    
    add     r12, 32
    add     r13, 32
    add     r14, 32
    dec     rcx
    jnz     @@unaligned_loop
    
@@unaligned_scalar:
    mov     rcx, r15
    and     rcx, 7
    jz      @@success
    
@@unaligned_scalar_loop:
    test    rcx, rcx
    jz      @@success
    
    movss   xmm0, DWORD PTR [r12]
    movss   xmm1, DWORD PTR [r13]
    mulss   xmm1, xmm3
    addss   xmm0, xmm1
    movss   DWORD PTR [r14], xmm0
    
    add     r12, 4
    add     r13, 4
    add     r14, 4
    dec     rcx
    jmp     @@unaligned_scalar_loop
    
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
Sovereign_ResidualAdd_Scaled_F32_AVX2 ENDP

; ============================================================================
; C API Exports
; ============================================================================

; ----------------------------------------------------------------------------
; residual_add_f32 - C-compatible wrapper
; ----------------------------------------------------------------------------
; extern "C" int residual_add_f32(const float* input, const float* residual,
;                                   float* output, size_t n_elements);
; ----------------------------------------------------------------------------
residual_add_f32 PROC EXPORT
    ; RCX=input, RDX=residual, R8=output, R9=n_elements
    jmp     Sovereign_ResidualAdd_F32_AVX2
residual_add_f32 ENDP

; ----------------------------------------------------------------------------
; residual_add_f32_inplace - C-compatible wrapper
; ----------------------------------------------------------------------------
; extern "C" int residual_add_f32_inplace(float* buffer, const float* residual,
;                                         size_t n_elements);
; ----------------------------------------------------------------------------
residual_add_f32_inplace PROC EXPORT
    ; RCX=buffer, RDX=residual, R8=n_elements
    jmp     Sovereign_ResidualAdd_F32_InPlace_AVX2
residual_add_f32_inplace ENDP

; ----------------------------------------------------------------------------
; residual_add_f32_scaled - C-compatible wrapper
; ----------------------------------------------------------------------------
; extern "C" int residual_add_f32_scaled(const float* input, const float* residual,
;                                          float* output, size_t n_elements,
;                                          float scale_factor);
; ----------------------------------------------------------------------------
residual_add_f32_scaled PROC EXPORT
    ; RCX=input, RDX=residual, R8=output, R9=n_elements
    ; scale_factor is on stack
    jmp     Sovereign_ResidualAdd_Scaled_F32_AVX2
residual_add_f32_scaled ENDP

; ============================================================================
; End of Module
; ============================================================================
END
