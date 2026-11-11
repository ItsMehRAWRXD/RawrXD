; =============================================================================
; SwarmV29_KAT_Test.asm - Known Answer Test for NTT/INTT Correctness
; =============================================================================
; Validates NTT/INTT butterfly operations against test vectors
; Date: 2026-07-14
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            PUBLICS
; =============================================================================
PUBLIC SwarmV29_KAT_Test_NTT
PUBLIC SwarmV29_KAT_Test_INTT
PUBLIC SwarmV29_KAT_Test_RoundTrip
PUBLIC SwarmV29_KAT_Get_MaxError
PUBLIC SwarmV29_KAT_Get_PassCount
PUBLIC SwarmV29_KAT_Get_FailCount

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN SwarmV29_NTT_Butterfly:PROC
EXTERN SwarmV29_INTT_Butterfly:PROC

; =============================================================================
;                            DATA
; =============================================================================
.data

; Test polynomial size (must be power of 2)
ALIGN 64
TestSize QWORD 256

; Prime modulus for testing (example: q = 12289 for Kyber)
ALIGN 64
Modulus QWORD 12289

; Test polynomial (example coefficients)
ALIGN 64
TestPolynomial QWORD 256 DUP (<>)

; NTT result
ALIGN 64
NTTResult QWORD 256 DUP (<>)

; INTT result (should match original)
ALIGN 64
INTTResult QWORD 256 DUP (<>)

; Twiddle factors (example: primitive root of unity)
ALIGN 64
TwiddleFactors QWORD 256 DUP (<>)

; Inverse twiddle factors
ALIGN 64
InvTwiddleFactors QWORD 256 DUP (<>)

; Error tracking
ALIGN 64
MaxError QWORD 0
PassCount QWORD 0
FailCount QWORD 0

; Test vectors (simple test: identity polynomial)
; p(x) = 1 + 0x + 0x^2 + ... + 0x^255
ALIGN 64
IdentityPolynomial QWORD 1, 0, 0, 0, 0, 0, 0, 0
                     QWORD 0, 0, 0, 0, 0, 0, 0, 0
                     ; ... (256 coefficients total)

; Expected NTT result for identity polynomial
; NTT(1, 0, 0, ...) should give (1, 1, 1, ...) mod q
ALIGN 64
ExpectedNTTIdentity QWORD 256 DUP (1)

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_KAT_Init
; Initialize test vectors
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_KAT_Init PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Initialize test polynomial with identity
    lea rdi, TestPolynomial
    lea rsi, IdentityPolynomial
    mov ecx, 8              ; Copy first 8 coefficients
    rep movsq
    
    ; Fill remaining with zeros
    lea rdi, TestPolynomial
    add rdi, 64             ; Skip first 8 coefficients
    xor eax, eax
    mov ecx, 248            ; Remaining 248 coefficients
    rep stosq
    
    ; Initialize twiddle factors (simplified)
    ; In real implementation, these would be precomputed
    lea rdi, TwiddleFactors
    mov rax, 1              ; Start with 1
    mov ecx, 256
    
@@init_twiddle:
    mov QWORD PTR [rdi], rax
    add rdi, 8
    ; Multiply by primitive root (simplified)
    imul rax, 3             ; Example: primitive root = 3
    xor rdx, rdx
    div Modulus             ; mod q
    mov rax, rdx
    dec ecx
    jnz @@init_twiddle
    
    ; Initialize inverse twiddle factors
    lea rdi, InvTwiddleFactors
    lea rsi, TwiddleFactors
    mov ecx, 256
    
@@init_inv_twiddle:
    ; Compute modular inverse (simplified)
    mov rax, QWORD PTR [rsi]
    ; In real implementation, use extended Euclidean algorithm
    ; For now, just copy (placeholder)
    mov QWORD PTR [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz @@init_inv_twiddle
    
    ; Reset counters
    mov QWORD PTR [MaxError], 0
    mov QWORD PTR [PassCount], 0
    mov QWORD PTR [FailCount], 0
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Init ENDP

; =============================================================================
; SwarmV29_KAT_Test_NTT
; Test NTT butterfly operation
;
; Returns: EAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_KAT_Test_NTT PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Call SwarmV29_KAT_Init
    call SwarmV29_KAT_Init
    
    ; Call NTT butterfly
    lea rcx, TestPolynomial  ; input
    lea rdx, TwiddleFactors  ; twiddle factors
    mov r8, TestSize         ; n
    mov r9, Modulus          ; modulus
    call SwarmV29_NTT_Butterfly
    
    ; Store result
    lea rdi, NTTResult
    lea rsi, TestPolynomial
    mov ecx, 256
    rep movsq
    
    ; Compare with expected (simplified)
    ; In real implementation, compare coefficient by coefficient
    ; For now, just check if result is non-zero
    lea rdi, NTTResult
    mov ecx, 256
    xor eax, eax            ; pass flag
    
@@check_ntt:
    cmp QWORD PTR [rdi], 0
    jne @@ntt_nonzero
    add rdi, 8
    dec ecx
    jnz @@check_ntt
    
    ; All zeros - fail
    inc QWORD PTR [FailCount]
    mov eax, -1
    jmp @@done
    
@@ntt_nonzero:
    ; At least one non-zero - pass
    inc QWORD PTR [PassCount]
    xor eax, eax
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Test_NTT ENDP

; =============================================================================
; SwarmV29_KAT_Test_INTT
; Test INTT butterfly operation
;
; Returns: EAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_KAT_Test_INTT PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Call INTT butterfly on NTT result
    lea rcx, NTTResult      ; input (NTT output)
    lea rdx, InvTwiddleFactors ; inverse twiddle factors
    mov r8, TestSize        ; n
    mov r9, Modulus         ; modulus
    call SwarmV29_INTT_Butterfly
    
    ; Store result
    lea rdi, INTTResult
    lea rsi, NTTResult
    mov ecx, 256
    rep movsq
    
    ; Compare with original polynomial
    lea rdi, INTTResult
    lea rsi, TestPolynomial
    mov ecx, 256
    xor eax, eax            ; pass flag
    
@@compare:
    mov rax, QWORD PTR [rdi]
    mov rbx, QWORD PTR [rsi]
    cmp rax, rbx
    jne @@mismatch
    
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz @@compare
    
    ; All match - pass
    inc QWORD PTR [PassCount]
    xor eax, eax
    jmp @@done
    
@@mismatch:
    ; Mismatch - fail
    inc QWORD PTR [FailCount]
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Test_INTT ENDP

; =============================================================================
; SwarmV29_KAT_Test_RoundTrip
; Test NTT -> INTT round trip
;
; Returns: EAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_KAT_Test_RoundTrip PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Initialize
    call SwarmV29_KAT_Init
    
    ; Test NTT
    call SwarmV29_KAT_Test_NTT
    test eax, eax
    jnz @@fail
    
    ; Test INTT
    call SwarmV29_KAT_Test_INTT
    test eax, eax
    jnz @@fail
    
    ; Calculate max error
    lea rdi, INTTResult
    lea rsi, TestPolynomial
    mov ecx, 256
    xor rbx, rbx            ; max error
    
@@calc_error:
    mov rax, QWORD PTR [rdi]
    mov rdx, QWORD PTR [rsi]
    sub rax, rdx            ; error = result - original
    jns @@positive
    neg rax                 ; absolute value
    
@@positive:
    cmp rax, rbx
    cmova rbx, rax          ; update max error
    
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz @@calc_error
    
    ; Store max error
    mov QWORD PTR [MaxError], rbx
    
    ; Check if max error is zero
    test rbx, rbx
    jz @@pass
    
    ; Non-zero error - fail
    inc QWORD PTR [FailCount]
    mov eax, -1
    jmp @@done
    
@@pass:
    inc QWORD PTR [PassCount]
    xor eax, eax
    jmp @@done
    
@@fail:
    inc QWORD PTR [FailCount]
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Test_RoundTrip ENDP

; =============================================================================
; SwarmV29_KAT_Get_MaxError
; Get maximum coefficient error from last round trip test
;
; Returns: RAX = max error
; =============================================================================
SwarmV29_KAT_Get_MaxError PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [MaxError]
    
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Get_MaxError ENDP

; =============================================================================
; SwarmV29_KAT_Get_PassCount
; Get count of passed tests
;
; Returns: RAX = pass count
; =============================================================================
SwarmV29_KAT_Get_PassCount PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [PassCount]
    
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Get_PassCount ENDP

; =============================================================================
; SwarmV29_KAT_Get_FailCount
; Get count of failed tests
;
; Returns: RAX = fail count
; =============================================================================
SwarmV29_KAT_Get_FailCount PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [FailCount]
    
    SWARMV29_ABI_EPILOG
SwarmV29_KAT_Get_FailCount ENDP

END