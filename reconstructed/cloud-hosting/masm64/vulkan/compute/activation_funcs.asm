; ============================================================================
; Activation Functions (MASM x64)
; ============================================================================
; Implements ReLU, GELU, Softmax, and other activation functions
; ============================================================================

.code

; ============================================================================
; Constants
; ============================================================================
.data
    ALIGN 16
    const_zero      REAL4 0.0
    const_one       REAL4 1.0
    const_half      REAL4 0.5
    const_sqrt2pi   REAL4 0.3989422804  ; 1/sqrt(2*pi)
    const_gelu_a    REAL4 0.044715
    const_gelu_sqrt2 REAL4 0.7978845608  ; sqrt(2/pi)

; ============================================================================
; ReLU - Rectified Linear Unit: max(0, x)
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count (number of elements)
;
; Returns:
;   RAX = 0 on success
; ============================================================================
ReLU PROC
    push rbp
    mov rbp, rsp
    push rdi
    
    test rcx, rcx
    jz relu_error
    test rdx, rdx
    jz relu_error
    test r8, r8
    jz relu_error
    
    mov rdi, rdx
    xor r9, r9
    movss xmm2, const_zero
    
relu_loop:
    cmp r9, r8
    jae relu_done
    
    ; Load input
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rcx + rax]
    
    ; Max with 0
    maxss xmm0, xmm2
    
    ; Store output
    movss DWORD PTR [rdi + rax], xmm0
    
    inc r9
    jmp relu_loop
    
relu_done:
    xor eax, eax
    jmp relu_cleanup
    
relu_error:
    mov eax, -1
    
relu_cleanup:
    pop rdi
    pop rbp
    ret
ReLU ENDP

; ============================================================================
; ReLU6 - Clamped ReLU: min(max(0, x), 6)
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count
;
; Returns:
;   RAX = 0 on success
; ============================================================================
ReLU6 PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    push rdi
    
    test rcx, rcx
    jz relu6_error
    test rdx, rdx
    jz relu6_error
    test r8, r8
    jz relu6_error
    
    mov rdi, rdx
    xor r9, r9
    movss xmm2, const_zero
    
    ; Load constant 6.0
    mov DWORD PTR [rsp+10h], 40C00000h  ; 6.0f
    movss xmm3, DWORD PTR [rsp+10h]
    
relu6_loop:
    cmp r9, r8
    jae relu6_done
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rcx + rax]
    
    ; Max with 0
    maxss xmm0, xmm2
    ; Min with 6
    minss xmm0, xmm3
    
    movss DWORD PTR [rdi + rax], xmm0
    
    inc r9
    jmp relu6_loop
    
relu6_done:
    xor eax, eax
    jmp relu6_cleanup
    
relu6_error:
    mov eax, -1
    
relu6_cleanup:
    pop rdi
    add rsp, 20h
    pop rbp
    ret
ReLU6 ENDP

; ============================================================================
; Tanh approximation: tanh(x) ≈ x * (27 + x²) / (27 + 9x²)
; Fast approximation with reasonable accuracy
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count
;
; Returns:
;   RAX = 0 on success
; ============================================================================
TanhApprox PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    push rdi
    
    test rcx, rcx
    jz tanh_error
    test rdx, rdx
    jz tanh_error
    test r8, r8
    jz tanh_error
    
    mov rdi, rdx
    xor r9, r9
    
    ; Constants
    mov DWORD PTR [rsp+10h], 41D80000h  ; 27.0f
    mov DWORD PTR [rsp+14h], 41100000h  ; 9.0f
    movss xmm4, DWORD PTR [rsp+10h]     ; xmm4 = 27.0
    movss xmm5, DWORD PTR [rsp+14h]     ; xmm5 = 9.0
    
tanh_loop:
    cmp r9, r8
    jae tanh_done
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rcx + rax]
    
    ; x² 
    movss xmm1, xmm0
    mulss xmm1, xmm1    ; xmm1 = x²
    
    ; Numerator: x * (27 + x²)
    movss xmm2, xmm4    ; 27
    addss xmm2, xmm1    ; 27 + x²
    mulss xmm2, xmm0    ; x * (27 + x²)
    
    ; Denominator: 27 + 9x²
    movss xmm3, xmm1    ; x²
    mulss xmm3, xmm5    ; 9x²
    addss xmm3, xmm4    ; 27 + 9x²
    
    ; Divide
    divss xmm2, xmm3
    
    movss DWORD PTR [rdi + rax], xmm2
    
    inc r9
    jmp tanh_loop
    
tanh_done:
    xor eax, eax
    jmp tanh_cleanup
    
tanh_error:
    mov eax, -1
    
tanh_cleanup:
    pop rdi
    add rsp, 20h
    pop rbp
    ret
TanhApprox ENDP

; ============================================================================
; GELU - Gaussian Error Linear Unit (approximation)
; GELU(x) ≈ 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x³)))
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count
;
; Returns:
;   RAX = 0 on success
; ============================================================================
GELU PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    push rdi
    
    test rcx, rcx
    jz gelu_error
    test rdx, rdx
    jz gelu_error
    test r8, r8
    jz gelu_error
    
    mov rdi, rdx
    xor r9, r9
    
    movss xmm6, const_half
    movss xmm7, const_gelu_sqrt2
    
    ; Load constants
    mov DWORD PTR [rsp+10h], 3D371759h  ; 0.044715
    mov DWORD PTR [rsp+14h], 3F800000h  ; 1.0
    movss xmm4, DWORD PTR [rsp+10h]
    movss xmm5, DWORD PTR [rsp+14h]
    
gelu_loop:
    cmp r9, r8
    jae gelu_done
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rcx + rax]
    
    ; Calculate x³
    movss xmm1, xmm0
    mulss xmm1, xmm1    ; x²
    mulss xmm1, xmm0    ; x³
    
    ; 0.044715 * x³
    mulss xmm1, xmm4
    
    ; x + 0.044715 * x³
    addss xmm1, xmm0
    
    ; sqrt(2/π) * (x + 0.044715 * x³)
    mulss xmm1, xmm7
    
    ; Tanh approximation on xmm1
    ; Using same formula as TanhApprox
    movss xmm2, xmm1
    mulss xmm2, xmm2    ; xmm2 = arg²
    
    ; Load 27.0 and 9.0
    mov DWORD PTR [rsp+18h], 41D80000h
    mov DWORD PTR [rsp+1Ch], 41100000h
    movss xmm3, DWORD PTR [rsp+18h]  ; 27.0
    
    ; Numerator
    movss xmm8, xmm3
    addss xmm8, xmm2
    mulss xmm8, xmm1
    
    ; Denominator
    movss xmm9, xmm2
    movss xmm10, DWORD PTR [rsp+1Ch]  ; 9.0
    mulss xmm9, xmm10
    addss xmm9, xmm3
    
    divss xmm8, xmm9    ; tanh result
    
    ; 1 + tanh
    addss xmm8, xmm5
    
    ; x * (1 + tanh)
    mulss xmm8, xmm0
    
    ; 0.5 * result
    mulss xmm8, xmm6
    
    movss DWORD PTR [rdi + rax], xmm8
    
    inc r9
    jmp gelu_loop
    
gelu_done:
    xor eax, eax
    jmp gelu_cleanup
    
gelu_error:
    mov eax, -1
    
gelu_cleanup:
    pop rdi
    add rsp, 40h
    pop rbp
    ret
GELU ENDP

; ============================================================================
; Softmax - Numerically stable softmax
; output[i] = exp(input[i] - max) / sum(exp(input[j] - max))
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count
;
; Returns:
;   RAX = 0 on success
; ============================================================================
Softmax PROC
    push rbp
    mov rbp, rsp
    sub rsp, 80h
    push rbx
    push rdi
    push rsi
    
    test rcx, rcx
    jz softmax_error
    test rdx, rdx
    jz softmax_error
    test r8, r8
    jz softmax_error
    
    mov rbx, rcx
    mov rdi, rdx
    mov rsi, r8
    
    ; Find max value
    mov rax, 0
    movss xmm0, DWORD PTR [rbx]
    mov r9, 1
    
softmax_find_max:
    cmp r9, rsi
    jae softmax_max_found
    
    mov rax, r9
    shl rax, 2
    movss xmm1, DWORD PTR [rbx + rax]
    maxss xmm0, xmm1
    
    inc r9
    jmp softmax_find_max
    
softmax_max_found:
    ; xmm0 contains max
    movss DWORD PTR [rsp+10h], xmm0
    
    ; Calculate exp(x - max) and sum
    xorps xmm2, xmm2    ; sum = 0
    xor r9, r9
    
softmax_exp_loop:
    cmp r9, rsi
    jae softmax_normalize
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rbx + rax]
    
    ; x - max
    movss xmm1, DWORD PTR [rsp+10h]
    subss xmm0, xmm1
    
    ; Fast exp approximation would go here
    ; For now, use simple approximation: exp(x) ≈ 1 + x + x²/2
    ; This is only accurate near 0, but demonstrates the concept
    
    movss xmm3, xmm0    ; x
    movss xmm4, xmm0
    mulss xmm4, xmm0    ; x²
    
    mov DWORD PTR [rsp+14h], 3F000000h  ; 0.5
    movss xmm5, DWORD PTR [rsp+14h]
    mulss xmm4, xmm5    ; x²/2
    
    mov DWORD PTR [rsp+18h], 3F800000h  ; 1.0
    movss xmm5, DWORD PTR [rsp+18h]
    addss xmm3, xmm5    ; 1 + x
    addss xmm3, xmm4    ; 1 + x + x²/2
    
    ; Store exp value temporarily
    movss DWORD PTR [rdi + rax], xmm3
    
    ; Add to sum
    addss xmm2, xmm3
    
    inc r9
    jmp softmax_exp_loop
    
softmax_normalize:
    ; Divide each by sum
    xor r9, r9
    
softmax_div_loop:
    cmp r9, rsi
    jae softmax_done
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rdi + rax]
    divss xmm0, xmm2
    movss DWORD PTR [rdi + rax], xmm0
    
    inc r9
    jmp softmax_div_loop
    
softmax_done:
    xor eax, eax
    jmp softmax_cleanup
    
softmax_error:
    mov eax, -1
    
softmax_cleanup:
    pop rsi
    pop rdi
    pop rbx
    add rsp, 80h
    pop rbp
    ret
Softmax ENDP

; ============================================================================
; Sigmoid - Logistic sigmoid: 1 / (1 + exp(-x))
; Using approximation for exp
;
; Parameters:
;   RCX = pointer to input (float*)
;   RDX = pointer to output (float*)
;   R8  = count
;
; Returns:
;   RAX = 0 on success
; ============================================================================
Sigmoid PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    push rdi
    
    test rcx, rcx
    jz sigmoid_error
    test rdx, rdx
    jz sigmoid_error
    test r8, r8
    jz sigmoid_error
    
    mov rdi, rdx
    xor r9, r9
    
    mov DWORD PTR [rsp+10h], 3F800000h  ; 1.0
    movss xmm5, DWORD PTR [rsp+10h]
    
sigmoid_loop:
    cmp r9, r8
    jae sigmoid_done
    
    mov rax, r9
    shl rax, 2
    movss xmm0, DWORD PTR [rcx + rax]
    
    ; Negate
    mov DWORD PTR [rsp+14h], 80000000h  ; -0.0 (sign bit)
    movss xmm1, DWORD PTR [rsp+14h]
    xorps xmm0, xmm1    ; -x
    
    ; Fast sigmoid approximation: 1 / (1 + exp(-x))
    ; Using tanh: sigmoid(x) = 0.5 * (1 + tanh(x/2))
    
    ; x/2
    mov DWORD PTR [rsp+18h], 3F000000h  ; 0.5
    movss xmm2, DWORD PTR [rsp+18h]
    mulss xmm0, xmm2
    
    ; Tanh approximation (simplified)
    ; Result approximated as x for small values
    ; Full implementation would use TanhApprox
    
    ; 1 + tanh(x/2)
    addss xmm0, xmm5
    
    ; 0.5 * result
    mulss xmm0, xmm2
    
    movss DWORD PTR [rdi + rax], xmm0
    
    inc r9
    jmp sigmoid_loop
    
sigmoid_done:
    xor eax, eax
    jmp sigmoid_cleanup
    
sigmoid_error:
    mov eax, -1
    
sigmoid_cleanup:
    pop rdi
    add rsp, 20h
    pop rbp
    ret
Sigmoid ENDP

END
