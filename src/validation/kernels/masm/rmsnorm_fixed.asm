; ============================================================================
; rmsnorm_fixed.asm - Corrected RMSNorm implementation
; ============================================================================
; Fixes bug where weights pointer wasn't reset before normalize loop
; 
; Algorithm:
;   1. Compute sum of squares: sum_sq = sum(x[i]^2)
;   2. Compute mean square: mean_sq = sum_sq / n
;   3. Compute RMS: rms = sqrt(mean_sq + epsilon)
;   4. Normalize: y[i] = x[i] / rms * weight[i]
; ============================================================================

OPTION CASEMAP:NONE

.const
ALIGN 16
epsilon_const REAL4 1.0e-5

.code

; ============================================================================
; MASM_RMSNorm_Fixed - Corrected RMSNorm with AVX2
; ============================================================================
; Parameters:
;   RCX = float* input (32-byte aligned)
;   RDX = float* output (32-byte aligned)
;   R8  = float* weights (32-byte aligned)
;   R9  = size_t size (multiple of 8)
; Returns: RAX = 0 on success
; ============================================================================

MASM_RMSNorm_Fixed PROC FRAME
    ; Prologue - CRITICAL: Save non-volatile registers BEFORE .endprolog
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Validate parameters
    test rcx, rcx
    jz error_null
    test rdx, rdx
    jz error_null
    test r8, r8
    jz error_null
    test r9, r9
    jz error_zero
    
    ; Check alignment
    test rcx, 31
    jnz error_align
    test rdx, 31
    jnz error_align
    test r8, 31
    jnz error_align
    
    ; Check size
    test r9, 7
    jnz error_size

    ; Save parameters
    mov rsi, rcx          ; rsi = input
    mov rdi, rdx          ; rdi = output
    mov r12, r8           ; r12 = weights
    mov rbx, r9           ; rbx = size
    mov r13, r9           ; r13 = original size (for later)
    mov r14, r8           ; r14 = original weights pointer

    ; Phase 1: Compute sum of squares
    vxorps ymm0, ymm0, ymm0    ; ymm0 = sum_sq = 0

sum_loop:
    cmp rbx, 0
    jle sum_done
    
    vmovaps ymm1, YMMWORD PTR [rsi]
    vmulps ymm2, ymm1, ymm1    ; ymm2 = x^2
    vaddps ymm0, ymm0, ymm2    ; sum_sq += x^2
    
    add rsi, 32
    sub rbx, 8
    jmp sum_loop

sum_done:
    ; Horizontal reduction of ymm0
    vextractf128 xmm1, ymm0, 1
    vaddps xmm0, xmm0, xmm1
    vmovshdup xmm1, xmm0
    vaddps xmm0, xmm0, xmm1
    vmovhlps xmm1, xmm1, xmm0
    vaddps xmm0, xmm0, xmm1
    
    ; xmm0[0] = total sum of squares
    
    ; Compute mean_sq = sum_sq / n
    vcvtsi2ss xmm1, xmm1, r13
    vdivss xmm0, xmm0, xmm1    ; xmm0 = mean_sq
    
    ; Add epsilon
    vmovss xmm2, DWORD PTR [epsilon_const]
    vaddss xmm0, xmm0, xmm2    ; xmm0 = mean_sq + epsilon
    
    ; Compute rms = sqrt(mean_sq + epsilon)
    vsqrtss xmm0, xmm0, xmm0   ; xmm0 = rms
    
    ; Broadcast rms to all lanes
    vbroadcastss ymm3, xmm0      ; ymm3 = [rms, rms, ...]

    ; Phase 2: Normalize and apply weights
    ; Reset pointers
    mov rsi, rcx          ; reset input
    mov rdi, rdx          ; reset output
    mov r12, r14          ; reset weights (THIS WAS THE BUG!)
    mov rbx, r13          ; reset size

normalize_loop:
    cmp rbx, 0
    jle normalize_done
    
    vmovaps ymm0, YMMWORD PTR [rsi]    ; ymm0 = input
    vmovaps ymm1, YMMWORD PTR [r12]    ; ymm1 = weights
    
    ; y = x / rms
    vdivps ymm2, ymm0, ymm3
    
    ; y = y * weight
    vmulps ymm2, ymm2, ymm1
    
    vmovaps YMMWORD PTR [rdi], ymm2
    
    add rsi, 32
    add rdi, 32
    add r12, 32
    sub rbx, 8
    jmp normalize_loop

normalize_done:
    xor rax, rax
    jmp cleanup

error_null:
    mov rax, 1
    jmp cleanup

error_zero:
    mov rax, 2
    jmp cleanup

error_align:
    mov rax, 3
    jmp cleanup

error_size:
    mov rax, 4

cleanup:
    vzeroupper
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    add rsp, 32
    pop rbp
    ret

MASM_RMSNorm_Fixed ENDP

END
