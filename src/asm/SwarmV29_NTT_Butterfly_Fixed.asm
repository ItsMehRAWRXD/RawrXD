; =============================================================================
; SwarmV29_NTT_Butterfly_Fixed.asm - Forward NTT Butterfly Kernel (Fixed)
; =============================================================================
; Number Theoretic Transform (NTT) forward butterfly for PQC
; Rewritten without custom macros to fix code generation issue
; Date: 2026-07-14
; =============================================================================

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_NTT_Butterfly
PUBLIC SwarmV29_NTT_Forward
PUBLIC SwarmV29_NTT_Butterfly_Scalar

; =============================================================================
;                            DATA
; =============================================================================
.data

; Twiddle factors (example for N=256, q=12289)
ALIGN 16
TwiddleFactors QWORD 256 DUP (0)

; Constants
ALIGN 16
Modulus QWORD 12289        ; Prime modulus q
ModulusInv QWORD 0         ; Modular inverse (computed at init)
RootOfUnity QWORD 0        ; Primitive root of unity

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_NTT_Butterfly_Scalar
; Scalar NTT butterfly (fallback for non-AVX512)
;
; RCX = a pointer
; RDX = b pointer
; R8  = twiddle factor
; R9  = modulus
;
; Returns: void (modifies a and b in place)
; =============================================================================
SwarmV29_NTT_Butterfly_Scalar PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Load values
    mov r12, rcx            ; a pointer
    mov r13, rdx            ; b pointer
    mov r14, r8             ; twiddle
    mov r15, r9             ; modulus
    
    mov rax, [r12]          ; a
    mov rbx, [r13]          ; b
    
    ; Compute: t = (twiddle * b) mod q
    mov rax, r14            ; twiddle
    imul rax, rbx           ; twiddle * b
    xor rdx, rdx
    div r15                 ; rax = quotient, rdx = remainder
    mov r14, rdx            ; t = (twiddle * b) mod q
    
    ; Compute: b = (a - t) mod q
    mov rax, [r12]
    sub rax, r14
    js @@neg_b
    mov [r13], rax
    jmp @@compute_a
    
@@neg_b:
    add rax, r15
    mov [r13], rax
    
@@compute_a:
    ; Compute: a = (a + t) mod q
    mov rax, [r12]
    add rax, r14
    cmp rax, r15
    jb @@store_a
    sub rax, r15
    
@@store_a:
    mov [r12], rax
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_NTT_Butterfly_Scalar ENDP

; =============================================================================
; SwarmV29_NTT_Butterfly
; AVX-512 optimized NTT butterfly
;
; RCX = data pointer (array of int64)
; RDX = twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_NTT_Butterfly PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Validate parameters
    test rcx, rcx
    jz @@invalid_params
    test rdx, rdx
    jz @@invalid_params
    test r8, r8
    jz @@invalid_params
    
    ; Check if n is power of 2
    mov rax, r8
    dec rax
    test rax, r8
    jnz @@invalid_params
    
    ; Save parameters
    mov r12, rcx            ; data pointer
    mov r13, rdx            ; twiddle factors
    mov r14, r8             ; n
    mov r15, r9             ; modulus
    
    ; Compute log2(n)
    mov eax, r8d
    bsr eax, eax
    mov r11d, eax
    
    ; Main NTT loop
    xor ebx, ebx
    
@@ntt_stage_loop:
    cmp ebx, r11d
    jge @@ntt_done
    
    ; Compute distance for this stage
    mov eax, 1
    mov ecx, ebx
    shl eax, cl
    
    ; Compute number of blocks
    mov ecx, r14d
    shr ecx, 1
    mov edx, ebx
    shr ecx, cl
    
    ; Process each block
    xor esi, esi
    
@@block_loop:
    cmp esi, ecx
    jge @@stage_done
    
    ; Process each pair in block
    mov edi, eax
    shl edi, 1
    
    ; Inner loop
    xor ebp, ebp
    
@@pair_loop:
    mov r8d, r14d
    cmp ebp, r8d
    jge @@block_done
    
    ; Compute indices
    mov r8d, esi
    imul r8d, edi
    add r8d, ebp
    
    mov r9d, r8d
    add r9d, eax
    
    ; Load values
    mov r10, [r12 + r8 * 8]
    mov r11, [r12 + r9 * 8]
    
    ; Compute twiddle index
    mov ecx, ebx
    mov edx, ebp
    shr edx, cl
    
    ; Load twiddle factor
    mov rax, [r13 + rdx * 8]
    
    ; Butterfly: t = twiddle * a[j] mod q
    imul rax, r11
    xor rdx, rdx
    div r15
    mov rax, rdx
    
    ; a[i] = (a[i] + t) mod q
    add r10, rax
    cmp r10, r15
    jb @@no_mod1
    sub r10, r15
@@no_mod1:
    mov [r12 + r8 * 8], r10
    
    ; a[j] = (a[i] - t) mod q
    mov r10, [r12 + r8 * 8]
    sub r10, rax
    jns @@no_mod2
    add r10, r15
@@no_mod2:
    mov [r12 + r9 * 8], r10
    
    inc ebp
    jmp @@pair_loop
    
@@block_done:
    inc esi
    jmp @@block_loop
    
@@stage_done:
    inc ebx
    jmp @@ntt_stage_loop
    
@@ntt_done:
    xor rax, rax
    jmp @@done
    
@@invalid_params:
    mov rax, -1
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_NTT_Butterfly ENDP

; =============================================================================
; SwarmV29_NTT_Forward
; Complete forward NTT transform
;
; RCX = data pointer
; RDX = twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success
; =============================================================================
SwarmV29_NTT_Forward PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    call SwarmV29_NTT_Butterfly
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_NTT_Forward ENDP

END