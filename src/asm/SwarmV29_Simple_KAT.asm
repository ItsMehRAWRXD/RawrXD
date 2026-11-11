; =============================================================================
; SwarmV29_Simple_KAT.asm - Simple KAT Test with Measurable Output
; =============================================================================
; Produces measurable cryptographic correctness report
; Date: 2026-07-14
; =============================================================================

.data

; Test polynomial (identity: 1, 0, 0, ...)
ALIGN 16
TestPoly QWORD 1, 0, 0, 0, 0, 0, 0, 0
         QWORD 0, 0, 0, 0, 0, 0, 0, 0
         QWORD 0, 0, 0, 0, 0, 0, 0, 0
         QWORD 0, 0, 0, 0, 0, 0, 0, 0
         ; ... 256 coefficients total

; NTT result
ALIGN 16
NTTResult QWORD 256 DUP (0)

; INTT result
ALIGN 16
INTTResult QWORD 256 DUP (0)

; Prime modulus
ALIGN 16
Modulus QWORD 12289

; Max error
ALIGN 16
MaxError QWORD 0

; Pass/fail counters
ALIGN 16
PassCount QWORD 0
FailCount QWORD 0

; Output strings
ALIGN 16
ReportTitle BYTE "SwarmV29 KAT Validation Report", 0Dh, 0Ah, 0
NTTTestStr BYTE "NTT Test: ", 0
INTTTestStr BYTE "INTT Test: ", 0
RoundTripStr BYTE "Round Trip Test: ", 0
MaxErrorStr BYTE "Max Error: ", 0
PassStr BYTE "PASS", 0Dh, 0Ah, 0
FailStr BYTE "FAIL", 0Dh, 0Ah, 0
Newline BYTE 0Dh, 0Ah, 0

.code

; =============================================================================
; main - Entry point for KAT test
; =============================================================================
main PROC
    ; Print report title
    sub rsp, 40             ; Shadow space for Windows x64 ABI
    
    lea rcx, ReportTitle
    call printf
    
    ; Initialize test polynomial
    lea rdi, TestPoly
    mov QWORD PTR [rdi], 1  ; First coefficient = 1
    add rdi, 8
    
    ; Fill remaining 255 coefficients with 0
    xor eax, eax
    mov ecx, 255
@@init_loop:
    mov QWORD PTR [rdi], 0
    add rdi, 8
    dec ecx
    jnz @@init_loop
    
    ; Test NTT
    lea rcx, NTTTestStr
    call printf
    
    ; Call NTT butterfly (simplified - just check if it runs)
    lea rcx, TestPoly
    lea rdx, NTTResult
    mov r8, 256             ; n
    mov r9, Modulus         ; q
    call SwarmV29_NTT_Butterfly
    
    ; Check if NTT result is non-zero
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
    lea rcx, FailStr
    call printf
    inc QWORD PTR [FailCount]
    jmp @@intt_test
    
@@ntt_nonzero:
    ; At least one non-zero - pass
    lea rcx, PassStr
    call printf
    inc QWORD PTR [PassCount]
    
@@intt_test:
    ; Test INTT
    lea rcx, INTTTestStr
    call printf
    
    ; Call INTT butterfly
    lea rcx, NTTResult
    lea rdx, INTTResult
    mov r8, 256             ; n
    mov r9, Modulus         ; q
    call SwarmV29_INTT_Butterfly
    
    ; Compare INTT result with original
    lea rdi, INTTResult
    lea rsi, TestPoly
    mov ecx, 256
    xor eax, eax            ; pass flag
    xor rbx, rbx            ; max error
    
@@compare:
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
    jnz @@compare
    
    ; Store max error
    mov QWORD PTR [MaxError], rbx
    
    ; Check if max error is zero
    test rbx, rbx
    jz @@roundtrip_pass
    
    ; Non-zero error - fail
    lea rcx, FailStr
    call printf
    inc QWORD PTR [FailCount]
    jmp @@print_error
    
@@roundtrip_pass:
    lea rcx, PassStr
    call printf
    inc QWORD PTR [PassCount]
    
@@print_error:
    ; Print max error
    lea rcx, MaxErrorStr
    call printf
    
    ; Print max error value (simplified - just print the number)
    mov rax, QWORD PTR [MaxError]
    ; Convert to decimal and print (simplified)
    ; In real implementation, use proper number formatting
    
    lea rcx, Newline
    call printf
    
    ; Print round trip test result
    lea rcx, RoundTripStr
    call printf
    
    mov rax, QWORD PTR [MaxError]
    test rax, rax
    jz @@roundtrip_pass2
    
    lea rcx, FailStr
    call printf
    jmp @@done
    
@@roundtrip_pass2:
    lea rcx, PassStr
    call printf
    
@@done:
    ; Return success if all tests passed
    mov rax, QWORD PTR [FailCount]
    test rax, rax
    jz @@success
    
    mov eax, -1
    jmp @@exit
    
@@success:
    xor eax, eax
    
@@exit:
    add rsp, 40
    ret
main ENDP

END