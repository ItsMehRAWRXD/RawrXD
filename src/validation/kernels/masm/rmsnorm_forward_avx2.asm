; ============================================================================
; RMSNorm_Forward_AVX2.asm
; ============================================================================
; RMS Normalization kernel with AVX2 optimization
; 
; Algorithm:
;   1. Compute sum of squares: sum_sq = sum(x[i]^2)
;   2. Compute mean square: mean_sq = sum_sq / n
;   3. Compute RMS: rms = sqrt(mean_sq + epsilon)
;   4. Normalize: y[i] = x[i] / rms * weight[i]
;
; Performance: 8 floats per iteration (AVX2 YMM registers)
; ============================================================================

_TEXT SEGMENT

; Export the symbol
PUBLIC MASM_RMSNorm_Forward_AVX2

; ============================================================================
; MASM_RMSNorm_Forward_AVX2
; ============================================================================
; Computes RMS normalization with AVX2 SIMD optimization
;
; Parameters:
;   RCX = float* input       (input data, must be 32-byte aligned)
;   RDX = float* output      (output data, must be 32-byte aligned)
;   R8  = float* weights     (weight vector, must be 32-byte aligned)
;   R9  = size_t size        (number of elements, must be multiple of 8)
;
; Returns:
;   RAX = 0 on success, non-zero error code on failure
;
; Error Codes:
;   1 = null pointer (input, output, or weights)
;   2 = zero size
;   3 = misaligned pointer (not 32-byte aligned)
;   4 = invalid size (not multiple of 8)
; ============================================================================

ALIGN 16
MASM_RMSNorm_Forward_AVX2 PROC
    ; Prologue - save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 40
    
    ; Validate parameters
    test rcx, rcx
    jz null_pointer_error
    test rdx, rdx
    jz null_pointer_error
    test r8, r8
    jz null_pointer_error
    test r9, r9
    jz zero_size_error
    
    ; Check alignment (32-byte)
    test rcx, 1Fh
    jnz misaligned_error
    test rdx, 1Fh
    jnz misaligned_error
    test r8, 1Fh
    jnz misaligned_error
    
    ; Check size (must be multiple of 8)
    test r9, 7
    jnz invalid_size_error
    
    ; Save parameters
    mov rsi, rcx          ; input pointer
    mov rdi, rdx          ; output pointer
    mov r12, r8           ; weights pointer
    mov rbx, r9           ; size
    
    ; Initialize accumulator for sum of squares
    vxorps ymm0, ymm0, ymm0    ; sum_sq = 0
    
    ; Phase 1: Compute sum of squares
    ; Process 8 floats per iteration
sum_squares_loop:
    test rbx, rbx
    jz sum_done
    
    ; Load 8 floats from input
    vmovaps ymm1, [rsi]
    
    ; Square each element
    vmulps ymm2, ymm1, ymm1
    
    ; Accumulate sum of squares
    vaddps ymm0, ymm0, ymm2
    
    ; Advance pointers
    add rsi, 32
    sub rbx, 8
    jmp sum_squares_loop
    
sum_done:
    ; Horizontal reduction: sum all 8 elements in YMM0
    ; ymm0 = [s0, s1, s2, s3, s4, s5, s6, s7]
    
    ; Step 1: Add high half to low half
    vextractf128 xmm1, ymm0, 1    ; xmm1 = [s4, s5, s6, s7]
    vaddps xmm0, xmm0, xmm1        ; xmm0 = [s0+s4, s1+s5, s2+s6, s3+s7]
    
    ; Step 2: Shuffle and add
    vmovshdup xmm2, xmm0           ; xmm2 = [s1+s5, s3+s7, s1+s5, s3+s7]
    vaddps xmm0, xmm0, xmm2        ; xmm0 = [s0+s4+s1+s5, s2+s6+s3+s7, ...]
    
    ; Step 3: Final reduction
    vmovhlps xmm2, xmm2, xmm0      ; xmm2 = [s2+s6+s3+s7, ...]
    vaddps xmm0, xmm0, xmm2        ; xmm0 = [total_sum, ...]
    
    ; xmm0 now contains the total sum of squares in the first element
    
    ; Compute mean square: mean_sq = sum_sq / n
    vcvtsi2ss xmm1, xmm1, r9       ; xmm1 = size (as float)
    vdivss xmm0, xmm0, xmm1        ; xmm0 = mean_sq
    
    ; Add epsilon (1e-5) for numerical stability
    ; Load epsilon constant
    vmovss xmm2, [epsilon]
    vaddss xmm0, xmm0, xmm2        ; xmm0 = mean_sq + epsilon
    
    ; Compute RMS: rms = sqrt(mean_sq + epsilon)
    vsqrtss xmm0, xmm0, xmm0       ; xmm0 = rms
    
    ; Broadcast RMS to all 8 positions
    vbroadcastss ymm3, xmm0        ; ymm3 = [rms, rms, rms, rms, rms, rms, rms, rms]
    
    ; Phase 2: Normalize and apply weights
    ; Reset pointers
    mov rsi, rcx          ; input pointer
    mov rdi, rdx          ; output pointer
    mov rbx, r9           ; size
    
normalize_loop:
    test rbx, rbx
    jz normalize_done
    
    ; Load 8 floats from input
    vmovaps ymm1, [rsi]
    
    ; Load 8 floats from weights
    vmovaps ymm2, [r12]
    
    ; Normalize: y = x / rms
    vdivps ymm1, ymm1, ymm3
    
    ; Apply weights: y = y * weight
    vmulps ymm1, ymm1, ymm2
    
    ; Store result
    vmovaps [rdi], ymm1
    
    ; Advance pointers
    add rsi, 32
    add rdi, 32
    add r12, 32
    sub rbx, 8
    jmp normalize_loop
    
normalize_done:
    ; Success
    xor rax, rax          ; return 0
    
    ; Epilogue
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
; Error handlers
null_pointer_error:
    mov rax, 1
    jmp epilogue
    
zero_size_error:
    mov rax, 2
    jmp epilogue
    
misaligned_error:
    mov rax, 3
    jmp epilogue
    
invalid_size_error:
    mov rax, 4
    
epilogue:
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

ALIGN 16
epsilon DD 1.0e-5

MASM_RMSNorm_Forward_AVX2 ENDP

_TEXT ENDS

END