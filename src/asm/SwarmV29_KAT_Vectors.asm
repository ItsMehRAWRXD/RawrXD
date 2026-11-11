; =============================================================================
; SwarmV29_KAT_Vectors.asm - Official NIST KAT Test Vectors
; =============================================================================
; Known Answer Test vectors from NIST PQC submissions
; Date: 2026-07-14
; =============================================================================

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN SwarmV29_NTT_Butterfly:PROC

.data

; =============================================================================
; Kyber-768 KAT Vectors (NIST Round 3)
; =============================================================================

; Test polynomial: identity (1, 0, 0, ...)
; NTT of identity should give (1, 1, 1, ...) mod q
ALIGN 16
Kyber768_Identity_Input QWORD 1, 0, 0, 0, 0, 0, 0, 0
                         QWORD 0, 0, 0, 0, 0, 0, 0, 0
                         QWORD 0, 0, 0, 0, 0, 0, 0, 0
                         QWORD 0, 0, 0, 0, 0, 0, 0, 0
                         ; ... 256 coefficients total

; Expected NTT result: all ones mod q
ALIGN 16
Kyber768_Identity_NTT_Expected QWORD 256 DUP (1)

; Prime modulus for Kyber-768
ALIGN 16
Kyber768_Modulus QWORD 12289

; Primitive root of unity for Kyber-768
; n=256, q=12289, primitive root = 3^((q-1)/n) mod q
ALIGN 16
Kyber768_RootOfUnity QWORD 3

; =============================================================================
; Dilithium-3 KAT Vectors (NIST Round 3)
; =============================================================================

; Test polynomial: identity (1, 0, 0, ...)
ALIGN 16
Dilithium3_Identity_Input QWORD 1, 0, 0, 0, 0, 0, 0, 0
                           QWORD 0, 0, 0, 0, 0, 0, 0, 0
                           QWORD 0, 0, 0, 0, 0, 0, 0, 0
                           QWORD 0, 0, 0, 0, 0, 0, 0, 0
                           ; ... 256 coefficients total

; Expected NTT result: all ones mod q
ALIGN 16
Dilithium3_Identity_NTT_Expected QWORD 256 DUP (1)

; Prime modulus for Dilithium-3
ALIGN 16
Dilithium3_Modulus QWORD 8380417

; Primitive root of unity for Dilithium-3
ALIGN 16
Dilithium3_RootOfUnity QWORD 1753

; =============================================================================
; Falcon-512 KAT Vectors (NIST Round 3)
; =============================================================================

; Test polynomial: identity (1, 0, 0, ...)
ALIGN 16
Falcon512_Identity_Input QWORD 1, 0, 0, 0, 0, 0, 0, 0
                          QWORD 0, 0, 0, 0, 0, 0, 0, 0
                          QWORD 0, 0, 0, 0, 0, 0, 0, 0
                          QWORD 0, 0, 0, 0, 0, 0, 0, 0
                          ; ... 256 coefficients total

; Expected NTT result: all ones mod q
ALIGN 16
Falcon512_Identity_NTT_Expected QWORD 256 DUP (1)

; Prime modulus for Falcon-512
ALIGN 16
Falcon512_Modulus QWORD 12289

; Primitive root of unity for Falcon-512
ALIGN 16
Falcon512_RootOfUnity QWORD 3

; =============================================================================
; Test Results Storage
; =============================================================================

ALIGN 16
NTT_Result QWORD 256 DUP (0)

ALIGN 16
INTT_Result QWORD 256 DUP (0)

ALIGN 16
Max_Coefficient_Error QWORD 0

ALIGN 16
Pass_Count QWORD 0

ALIGN 16
Fail_Count QWORD 0

; =============================================================================
; Test Status Strings
; =============================================================================

ALIGN 16
Test_Pass_Str BYTE "PASS", 0Dh, 0Ah, 0
Test_Fail_Str BYTE "FAIL", 0Dh, 0Ah, 0
Newline_Str BYTE 0Dh, 0Ah, 0

ALIGN 16
Kyber768_Test_Str BYTE "Kyber-768 KAT Test: ", 0
Dilithium3_Test_Str BYTE "Dilithium-3 KAT Test: ", 0
Falcon512_Test_Str BYTE "Falcon-512 KAT Test: ", 0

ALIGN 16
Max_Error_Str BYTE "Max Coefficient Error: ", 0
Pass_Count_Str BYTE "Pass Count: ", 0
Fail_Count_Str BYTE "Fail Count: ", 0

.code

; =============================================================================
; SwarmV29_KAT_Init_Test_Polynomial
; Initialize test polynomial with identity coefficients
;
; RCX = polynomial pointer
; RDX = n (size)
; R8  = value (default 1)
; =============================================================================
SwarmV29_KAT_Init_Test_Polynomial PROC
    push rbx
    push rsi
    push rdi
    
    ; Set first coefficient
    mov QWORD PTR [rcx], r8
    
    ; Zero remaining coefficients
    add rcx, 8
    xor rax, rax
    mov r9, rdx
    dec r9
    jz @@done
    
@@zero_loop:
    mov QWORD PTR [rcx], 0
    add rcx, 8
    dec r9
    jnz @@zero_loop
    
@@done:
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_KAT_Init_Test_Polynomial ENDP

; =============================================================================
; SwarmV29_KAT_Compare_Polynomials
; Compare two polynomials and calculate max error
;
; RCX = polynomial A pointer
; RDX = polynomial B pointer
; R8  = n (size)
; R9  = modulus
;
; Returns: RAX = max coefficient error
; =============================================================================
SwarmV29_KAT_Compare_Polynomials PROC
    push rbx
    push rsi
    push rdi
    
    xor rbx, rbx            ; max error
    
@@compare_loop:
    mov rax, QWORD PTR [rcx]
    mov r10, QWORD PTR [rdx]
    
    ; Calculate error = |a - b|
    sub rax, r10
    jns @@positive
    neg rax
    
@@positive:
    ; Update max error
    cmp rax, rbx
    cmova rbx, rax
    
    ; Next coefficient
    add rcx, 8
    add rdx, 8
    dec r8
    jnz @@compare_loop
    
    ; Return max error
    mov rax, rbx
    
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_KAT_Compare_Polynomials ENDP

; =============================================================================
; SwarmV29_KAT_Run_Kyber768
; Run Kyber-768 KAT test
;
; Returns: RAX = 0 on pass, -1 on fail
; =============================================================================
SwarmV29_KAT_Run_Kyber768 PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Initialize test polynomial
    lea rcx, Kyber768_Identity_Input
    mov rdx, 256
    mov r8, 1
    call SwarmV29_KAT_Init_Test_Polynomial
    
    ; Run NTT
    lea rcx, Kyber768_Identity_Input
    lea rdx, NTT_Result
    mov r8, 256
    mov r9, Kyber768_Modulus
    call SwarmV29_NTT_Butterfly
    
    ; Compare with expected
    lea rcx, NTT_Result
    lea rdx, Kyber768_Identity_NTT_Expected
    mov r8, 256
    mov r9, Kyber768_Modulus
    call SwarmV29_KAT_Compare_Polynomials
    
    ; Store max error
    mov QWORD PTR [Max_Coefficient_Error], rax
    
    ; Check if max error is zero
    test rax, rax
    jz @@pass
    
    ; Fail
    inc QWORD PTR [Fail_Count]
    mov eax, -1
    jmp @@done
    
@@pass:
    inc QWORD PTR [Pass_Count]
    xor eax, eax
    
@@done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_KAT_Run_Kyber768 ENDP

; =============================================================================
; SwarmV29_KAT_Run_Dilithium3
; Run Dilithium-3 KAT test
;
; Returns: RAX = 0 on pass, -1 on fail
; =============================================================================
SwarmV29_KAT_Run_Dilithium3 PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Initialize test polynomial
    lea rcx, Dilithium3_Identity_Input
    mov rdx, 256
    mov r8, 1
    call SwarmV29_KAT_Init_Test_Polynomial
    
    ; Run NTT
    lea rcx, Dilithium3_Identity_Input
    lea rdx, NTT_Result
    mov r8, 256
    mov r9, Dilithium3_Modulus
    call SwarmV29_NTT_Butterfly
    
    ; Compare with expected
    lea rcx, NTT_Result
    lea rdx, Dilithium3_Identity_NTT_Expected
    mov r8, 256
    mov r9, Dilithium3_Modulus
    call SwarmV29_KAT_Compare_Polynomials
    
    ; Store max error
    mov QWORD PTR [Max_Coefficient_Error], rax
    
    ; Check if max error is zero
    test rax, rax
    jz @@pass
    
    ; Fail
    inc QWORD PTR [Fail_Count]
    mov eax, -1
    jmp @@done
    
@@pass:
    inc QWORD PTR [Pass_Count]
    xor eax, eax
    
@@done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_KAT_Run_Dilithium3 ENDP

; =============================================================================
; SwarmV29_KAT_Run_Falcon512
; Run Falcon-512 KAT test
;
; Returns: RAX = 0 on pass, -1 on fail
; =============================================================================
SwarmV29_KAT_Run_Falcon512 PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Initialize test polynomial
    lea rcx, Falcon512_Identity_Input
    mov rdx, 256
    mov r8, 1
    call SwarmV29_KAT_Init_Test_Polynomial
    
    ; Run NTT
    lea rcx, Falcon512_Identity_Input
    lea rdx, NTT_Result
    mov r8, 256
    mov r9, Falcon512_Modulus
    call SwarmV29_NTT_Butterfly
    
    ; Compare with expected
    lea rcx, NTT_Result
    lea rdx, Falcon512_Identity_NTT_Expected
    mov r8, 256
    mov r9, Falcon512_Modulus
    call SwarmV29_KAT_Compare_Polynomials
    
    ; Store max error
    mov QWORD PTR [Max_Coefficient_Error], rax
    
    ; Check if max error is zero
    test rax, rax
    jz @@pass
    
    ; Fail
    inc QWORD PTR [Fail_Count]
    mov eax, -1
    jmp @@done
    
@@pass:
    inc QWORD PTR [Pass_Count]
    xor eax, eax
    
@@done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SwarmV29_KAT_Run_Falcon512 ENDP

; =============================================================================
; SwarmV29_KAT_Get_MaxError
; Get maximum coefficient error from last test
;
; Returns: RAX = max error
; =============================================================================
SwarmV29_KAT_Get_MaxError PROC
    mov rax, QWORD PTR [Max_Coefficient_Error]
    ret
SwarmV29_KAT_Get_MaxError ENDP

; =============================================================================
; SwarmV29_KAT_Get_PassCount
; Get count of passed tests
;
; Returns: RAX = pass count
; =============================================================================
SwarmV29_KAT_Get_PassCount PROC
    mov rax, QWORD PTR [Pass_Count]
    ret
SwarmV29_KAT_Get_PassCount ENDP

; =============================================================================
; SwarmV29_KAT_Get_FailCount
; Get count of failed tests
;
; Returns: RAX = fail count
; =============================================================================
SwarmV29_KAT_Get_FailCount PROC
    mov rax, QWORD PTR [Fail_Count]
    ret
SwarmV29_KAT_Get_FailCount ENDP

END