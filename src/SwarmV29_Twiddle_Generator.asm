; ==============================================================================
; SwarmV29_Twiddle_Generator.asm
; PHASE-29: Twiddle Factor Table Generation for NTT/INTT
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Generates both forward and inverse twiddle factor tables for the NTT.
; Forward: w^k mod Q (powers of primitive root of unity)
; Inverse: w^-k mod Q (powers of modular inverse)
;
; For Kyber-1024: Q = 3329, primitive root = 17, N = 256
; For Dilithium-5: Q = 8380417, primitive root varies
; ==============================================================================

.code

; ==============================================================================
; SwarmV29_Generate_Twiddle_Table
; Generates forward twiddle factors: w^k mod Q for k = 0, 1, ..., N/2 - 1
; ------------------------------------------------------------------------------
; Inputs:
;   RCX = Pointer to output buffer (64-byte aligned, must hold N/2 elements)
;   RDX = N (Size of transform, e.g., 256)
;   R8  = Q (Modulus)
;   R9  = Primitive Root (e.g., 17 for Kyber-1024)
;
; Clobbers: RAX, RBX, R10-R15
; Returns: void (table stored in [RCX])
; ==============================================================================
ALIGN 16
SwarmV29_Generate_Twiddle_Table PROC PUBLIC
    push rdi
    push rsi

    mov rdi, rcx                ; rdi = output buffer
    mov rsi, rdx                ; rsi = N
    shr rsi, 1                  ; rsi = N/2 (number of twiddle factors)

    ; Initialize: w^0 = 1
    mov rax, 1
    mov [rdi], rax              ; table[0] = 1

    ; Current power = primitive_root
    mov rbx, r9                 ; rbx = current power (starts at root)

    ; Generate w^1, w^2, ..., w^(N/2-1)
    mov r10, 1                  ; r10 = index counter

generate_loop:
    cmp r10, rsi
    jge done_generate

    ; Store current power
    mov [rdi + r10*8], rbx

    ; Compute next power: current * root mod Q
    mov rax, rbx
    imul rax, r9                ; current * root
    xor rdx, rdx
    div r8                      ; rax = (current * root) mod Q
    mov rbx, rdx                ; remainder is the new power

    inc r10
    jmp generate_loop

done_generate:
    pop rsi
    pop rdi
    ret
SwarmV29_Generate_Twiddle_Table ENDP

; ==============================================================================
; SwarmV29_Generate_Inverse_Twiddle_Table
; Generates inverse twiddle factors: w^-k mod Q for k = 0, 1, ..., N/2 - 1
; Uses Fermat's Little Theorem: w^-1 = w^(Q-2) mod Q
; ------------------------------------------------------------------------------
; Inputs:
;   RCX = Pointer to output buffer (64-byte aligned, must hold N/2 elements)
;   RDX = N (Size of transform, e.g., 256)
;   R8  = Q (Modulus)
;   R9  = Primitive Root (e.g., 17 for Kyber-1024)
;
; Clobbers: RAX, RBX, R10-R15
; Returns: void (table stored in [RCX])
; ==============================================================================
ALIGN 16
SwarmV29_Generate_Inverse_Twiddle_Table PROC PUBLIC
    push rdi
    push rsi
    push r12

    mov rdi, rcx                ; rdi = output buffer
    mov rsi, rdx                ; rsi = N
    shr rsi, 1                  ; rsi = N/2

    ; First, compute w^-1 = w^(Q-2) mod Q using modular exponentiation
    ; This is the modular inverse of the primitive root
    mov rax, r9                 ; base = primitive root
    mov rbx, r8
    sub rbx, 2                  ; exponent = Q - 2

    ; Fast modular exponentiation (binary exponentiation)
    mov r12, 1                  ; result = 1

exp_loop:
    cmp rbx, 0
    jle exp_done

    test rbx, 1
    jz exp_even

    ; result = (result * base) mod Q
    mov rcx, rax
    imul rcx, r12
    xor rdx, rdx
    div r8
    mov r12, rdx

exp_even:
    ; base = (base * base) mod Q
    imul rax, rax
    xor rdx, rdx
    div r8
    mov rax, rdx

    shr rbx, 1
    jmp exp_loop

exp_done:
    ; r12 now contains w^-1 (modular inverse of primitive root)
    ; Generate inverse twiddle table

    ; Initialize: (w^-1)^0 = 1
    mov rax, 1
    mov [rdi], rax              ; table[0] = 1

    ; Current power = w^-1
    mov rbx, r12                ; rbx = current power (starts at w^-1)

    mov r10, 1                  ; r10 = index counter

inv_generate_loop:
    cmp r10, rsi
    jge inv_done_generate

    ; Store current power
    mov [rdi + r10*8], rbx

    ; Compute next power: current * w^-1 mod Q
    mov rax, rbx
    imul rax, r12               ; current * w^-1
    xor rdx, rdx
    div r8                      ; rax = (current * w^-1) mod Q
    mov rbx, rdx                ; remainder is the new power

    inc r10
    jmp inv_generate_loop

inv_done_generate:
    pop r12
    pop rsi
    pop rdi
    ret
SwarmV29_Generate_Inverse_Twiddle_Table ENDP

; ==============================================================================
; SwarmV29_Compute_N_Inverse
; Computes N^-1 mod Q using Fermat's Little Theorem: N^-1 = N^(Q-2) mod Q
; ------------------------------------------------------------------------------
; Inputs:
;   RCX = N (Size of transform)
;   RDX = Q (Modulus)
;
; Returns: RAX = N^-1 mod Q
; ==============================================================================
ALIGN 16
SwarmV29_Compute_N_Inverse PROC PUBLIC
    push rbx
    push r12
    push r13
    push r14

    mov rax, rcx                ; base = N
    mov r13, rdx                ; r13 = Q (modulus, preserved)
    mov rbx, rdx
    sub rbx, 2                  ; exponent = Q - 2

    mov r12, 1                  ; result = 1

ninv_exp_loop:
    cmp rbx, 0
    jle ninv_exp_done

    test rbx, 1
    jz ninv_exp_even

    ; result = (result * base) mod Q
    mov r14, rax
    imul r14, r12               ; result * base
    xor rdx, rdx
    div r13                     ; divide by Q
    mov r12, rdx                ; result = remainder

ninv_exp_even:
    ; base = (base * base) mod Q
    imul rax, rax               ; base * base
    xor rdx, rdx
    div r13                     ; divide by Q
    mov rax, rdx                ; base = remainder

    shr rbx, 1
    jmp ninv_exp_loop

ninv_exp_done:
    mov rax, r12                ; return result

    pop r14
    pop r13
    pop r12
    pop rbx
    ret
SwarmV29_Compute_N_Inverse ENDP

END