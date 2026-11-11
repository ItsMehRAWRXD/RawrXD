; =============================================================================
; SwarmV29_KAT_Validate.asm - KAT Validation with Corrected NTT/INTT
; =============================================================================
; Tests corrected NTT/INTT implementation for zero-error round-trip
; Date: 2026-07-14
; =============================================================================

EXTERN SwarmV29_NTT_Transform:PROC
EXTERN SwarmV29_INTT_Transform:PROC
EXTERN SwarmV29_NTT_Init:PROC

.data

; Test polynomial
ALIGN 16
TestPoly QWORD 256 DUP (0)

; Kyber-768 modulus
ALIGN 16
KyberModulus QWORD 12289

; Test counters
ALIGN 16
PassCount QWORD 0
ALIGN 16
FailCount QWORD 0
ALIGN 16
MaxError QWORD 0

.code

; =============================================================================
; InitializeIdentityPolynomial
; Initialize polynomial with identity (1, 0, 0, ...)
; =============================================================================
InitializeIdentityPolynomial PROC
    push rbx
    push rsi
    push rdi
    
    lea rdi, TestPoly
    mov QWORD PTR [rdi], 1      ; First coefficient = 1
    
    ; Zero remaining 255 coefficients
    add rdi, 8
    xor rax, rax
    mov ecx, 255
    
@@zero_loop:
    mov QWORD PTR [rdi], rax
    add rdi, 8
    dec ecx
    jnz @@zero_loop
    
    pop rdi
    pop rsi
    pop rbx
    ret
InitializeIdentityPolynomial ENDP

; =============================================================================
; ComparePolynomials
; Compare TestPoly with expected identity
; Returns: RAX = max error (should be 0 for perfect round-trip)
; =============================================================================
ComparePolynomials PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    lea r12, TestPoly         ; result polynomial
    xor r13, r13              ; max error
    xor r14, r14              ; index
    
@@compare_loop:
    cmp r14, 256
    jge @@done
    
    ; Load coefficient
    mov rax, QWORD PTR [r12 + r14 * 8]
    
    ; Expected value: 1 for index 0, 0 for others
    cmp r14, 0
    je @@check_first
    
    ; Check if coefficient is 0
    test rax, rax
    jz @@next
    
    ; Error: expected 0, got rax
    mov r13, rax
    jmp @@next
    
@@check_first:
    ; Check if first coefficient is 1
    cmp rax, 1
    je @@next
    
    ; Error: expected 1, got rax
    mov rbx, rax
    sub rbx, 1
    jns @@abs_error
    neg rbx
    
@@abs_error:
    cmp rbx, r13
    cmova r13, rbx
    
@@next:
    inc r14
    jmp @@compare_loop
    
@@done:
    ; Return max error
    mov rax, r13
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ComparePolynomials ENDP

; =============================================================================
; main - KAT Validation Entry Point
; Returns: 0 if all tests pass, -1 if any fail
; =============================================================================
main PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Initialize counters
    mov QWORD PTR [PassCount], 0
    mov QWORD PTR [FailCount], 0
    mov QWORD PTR [MaxError], 0
    
    ; Initialize NTT/INTT
    call SwarmV29_NTT_Init
    
    ; Initialize test polynomial
    call InitializeIdentityPolynomial
    
    ; Run NTT
    lea rcx, TestPoly
    call SwarmV29_NTT_Transform
    
    ; Run INTT
    lea rcx, TestPoly
    call SwarmV29_INTT_Transform
    
    ; Compare result with original
    call ComparePolynomials
    mov QWORD PTR [MaxError], rax
    
    ; Check if max error is zero
    test rax, rax
    jz @@test_pass
    
    ; Test failed
    inc QWORD PTR [FailCount]
    mov eax, -1
    jmp @@done
    
@@test_pass:
    ; Test passed
    inc QWORD PTR [PassCount]
    xor eax, eax
    
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
main ENDP

END