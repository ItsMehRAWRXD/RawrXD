; =============================================================================
; SwarmV29_KAT_Entry.asm - KAT Test Entry Point
; =============================================================================
; Runs Known Answer Tests for NTT/INTT correctness validation
; Date: 2026-07-14
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            PUBLICS
; =============================================================================
PUBLIC main

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN SwarmV29_KAT_Init:PROC
EXTERN SwarmV29_KAT_Test_NTT:PROC
EXTERN SwarmV29_KAT_Test_INTT:PROC
EXTERN SwarmV29_KAT_Test_RoundTrip:PROC
EXTERN SwarmV29_KAT_Get_MaxError:PROC
EXTERN SwarmV29_KAT_Get_PassCount:PROC
EXTERN SwarmV29_KAT_Get_FailCount:PROC

; =============================================================================
;                            DATA
; =============================================================================
.data

ALIGN 16
TestTitle BYTE "SwarmV29 KAT Validation Report", 0Dh, 0Ah, 0
TestTitleLen QWORD $ - TestTitle

ALIGN 16
NTTTestLabel BYTE "NTT Butterfly Test: ", 0
NTTTestLabelLen QWORD $ - NTTTestLabel

ALIGN 16
INTTTestLabel BYTE "INTT Butterfly Test: ", 0
INTTTestLabelLen QWORD $ - INTTTestLabel

ALIGN 16
RoundTripLabel BYTE "Round Trip Test: ", 0
RoundTripLabelLen QWORD $ - RoundTripLabel

ALIGN 16
MaxErrorLabel BYTE "Max Coefficient Error: ", 0
MaxErrorLabelLen QWORD $ - MaxErrorLabel

ALIGN 16
PassCountLabel BYTE "Pass Count: ", 0
PassCountLabelLen QWORD $ - PassCountLabel

ALIGN 16
FailCountLabel BYTE "Fail Count: ", 0
FailCountLabelLen QWORD $ - FailCountLabel

ALIGN 16
PassMsg BYTE "PASS", 0Dh, 0Ah, 0
PassMsgLen QWORD $ - PassMsg

ALIGN 16
FailMsg BYTE "FAIL", 0Dh, 0Ah, 0
FailMsgLen QWORD $ - FailMsg

ALIGN 16
Newline BYTE 0Dh, 0Ah, 0
NewlineLen QWORD $ - Newline

; Test results
ALIGN 16
NTTResult QWORD 0
INTTResult QWORD 0
RoundTripResult QWORD 0
MaxErrorValue QWORD 0
PassCountValue QWORD 0
FailCountValue QWORD 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; main
; KAT test entry point
; =============================================================================
main PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Print test title
    sub rsp, 40             ; shadow space
    lea rcx, TestTitle
    call printf
    
    ; Initialize KAT tests
    call SwarmV29_KAT_Init
    
    ; Run NTT test
    lea rcx, NTTTestLabel
    call printf
    
    call SwarmV29_KAT_Test_NTT
    mov QWORD PTR [NTTResult], rax
    
    ; Print NTT result
    test rax, rax
    jz @@ntt_pass
    
    lea rcx, FailMsg
    call printf
    jmp @@intt_test
    
@@ntt_pass:
    lea rcx, PassMsg
    call printf
    
@@intt_test:
    ; Run INTT test
    lea rcx, INTTTestLabel
    call printf
    
    call SwarmV29_KAT_Test_INTT
    mov QWORD PTR [INTTResult], rax
    
    ; Print INTT result
    test rax, rax
    jz @@intt_pass
    
    lea rcx, FailMsg
    call printf
    jmp @@roundtrip_test
    
@@intt_pass:
    lea rcx, PassMsg
    call printf
    
@@roundtrip_test:
    ; Run round trip test
    lea rcx, RoundTripLabel
    call printf
    
    call SwarmV29_KAT_Test_RoundTrip
    mov QWORD PTR [RoundTripResult], rax
    
    ; Print round trip result
    test rax, rax
    jz @@roundtrip_pass
    
    lea rcx, FailMsg
    call printf
    jmp @@print_stats
    
@@roundtrip_pass:
    lea rcx, PassMsg
    call printf
    
@@print_stats:
    ; Get max error
    call SwarmV29_KAT_Get_MaxError
    mov QWORD PTR [MaxErrorValue], rax
    
    ; Get pass count
    call SwarmV29_KAT_Get_PassCount
    mov QWORD PTR [PassCountValue], rax
    
    ; Get fail count
    call SwarmV29_KAT_Get_FailCount
    mov QWORD PTR [FailCountValue], rax
    
    ; Print max error
    lea rcx, MaxErrorLabel
    call printf
    
    mov rax, QWORD PTR [MaxErrorValue]
    ; Convert to string and print (simplified)
    ; In real implementation, use proper number formatting
    
    lea rcx, Newline
    call printf
    
    ; Print pass count
    lea rcx, PassCountLabel
    call printf
    
    mov rax, QWORD PTR [PassCountValue]
    ; Convert to string and print (simplified)
    
    lea rcx, Newline
    call printf
    
    ; Print fail count
    lea rcx, FailCountLabel
    call printf
    
    mov rax, QWORD PTR [FailCountValue]
    ; Convert to string and print (simplified)
    
    lea rcx, Newline
    call printf
    
    ; Return success if all tests passed
    mov rax, QWORD PTR [FailCountValue]
    test rax, rax
    jz @@success
    
    ; Return failure
    mov eax, -1
    jmp @@done
    
@@success:
    xor eax, eax
    
@@done:
    SWARMV29_ABI_EPILOG
main ENDP

END