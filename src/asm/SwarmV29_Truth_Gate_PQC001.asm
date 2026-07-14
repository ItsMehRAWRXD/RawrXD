; =============================================================================
; SwarmV29_Truth_Gate_PQC001.asm - Truth Gate PQC-001 Test Runner
; =============================================================================
; Executes NIST KAT vectors and produces measurable cryptographic correctness report
; Date: 2026-07-14
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN SwarmV29_KAT_Run_Kyber768:PROC
EXTERN SwarmV29_KAT_Run_Dilithium3:PROC
EXTERN SwarmV29_KAT_Run_Falcon512:PROC
EXTERN SwarmV29_KAT_Get_MaxError:PROC
EXTERN SwarmV29_KAT_Get_PassCount:PROC
EXTERN SwarmV29_KAT_Get_FailCount:PROC

; =============================================================================
;                            DATA
; =============================================================================
.data

ALIGN 16
Report_Header BYTE "SwarmV29 Truth Gate PQC-001 Report", 0Dh, 0Ah, 0
Report_Header_Len QWORD $ - Report_Header

ALIGN 16
Separator BYTE "================================", 0Dh, 0Ah, 0
Separator_Len QWORD $ - Separator

ALIGN 16
Date_Str BYTE "Date: 2026-07-14", 0Dh, 0Ah, 0
Date_Str_Len QWORD $ - Date_Str

ALIGN 16
Test_Suite_Str BYTE "Test Suite: NIST PQC KAT Vectors", 0Dh, 0Ah, 0
Test_Suite_Str_Len QWORD $ - Test_Suite_Str

ALIGN 16
Kyber768_Test_Str BYTE "Kyber-768: ", 0
Kyber768_Test_Str_Len QWORD $ - Kyber768_Test_Str

ALIGN 16
Dilithium3_Test_Str BYTE "Dilithium-3: ", 0
Dilithium3_Test_Str_Len QWORD $ - Dilithium3_Test_Str

ALIGN 16
Falcon512_Test_Str BYTE "Falcon-512: ", 0
Falcon512_Test_Str_Len QWORD $ - Falcon512_Test_Str

ALIGN 16
Pass_Str BYTE "PASS", 0Dh, 0Ah, 0
Pass_Str_Len QWORD $ - Pass_Str

ALIGN 16
Fail_Str BYTE "FAIL", 0Dh, 0Ah, 0
Fail_Str_Len QWORD $ - Fail_Str

ALIGN 16
Max_Error_Str BYTE "Max Coefficient Error: ", 0
Max_Error_Str_Len QWORD $ - Max_Error_Str

ALIGN 16
Pass_Count_Str BYTE "Pass Count: ", 0
Pass_Count_Str_Len QWORD $ - Pass_Count_Str

ALIGN 16
Fail_Count_Str BYTE "Fail Count: ", 0
Fail_Count_Str_Len QWORD $ - Fail_Count_Str

ALIGN 16
Newline BYTE 0Dh, 0Ah, 0
Newline_Len QWORD $ - Newline

ALIGN 16
Conclusion_Str BYTE "Conclusion: ", 0
Conclusion_Str_Len QWORD $ - Conclusion_Str

ALIGN 16
All_Pass_Str BYTE "All KAT tests passed. Cryptographic correctness verified.", 0Dh, 0Ah, 0
All_Pass_Str_Len QWORD $ - All_Pass_Str

ALIGN 16
Some_Fail_Str BYTE "Some KAT tests failed. Cryptographic correctness NOT verified.", 0Dh, 0Ah, 0
Some_Fail_Str_Len QWORD $ - Some_Fail_Str

; Test results
ALIGN 16
Kyber768_Result QWORD 0
Dilithium3_Result QWORD 0
Falcon512_Result QWORD 0
Total_Pass_Count QWORD 0
Total_Fail_Count QWORD 0
Max_Error_Value QWORD 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; main - Truth Gate PQC-001 Entry Point
; =============================================================================
main PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Print report header
    sub rsp, 40             ; Shadow space for Windows x64 ABI
    
    lea rcx, Report_Header
    call printf
    
    lea rcx, Separator
    call printf
    
    lea rcx, Date_Str
    call printf
    
    lea rcx, Test_Suite_Str
    call printf
    
    lea rcx, Separator
    call printf
    
    lea rcx, Newline
    call printf
    
    ; Run Kyber-768 test
    lea rcx, Kyber768_Test_Str
    call printf
    
    call SwarmV29_KAT_Run_Kyber768
    mov QWORD PTR [Kyber768_Result], rax
    
    ; Print result
    test rax, rax
    jz @@kyber768_pass
    
    lea rcx, Fail_Str
    call printf
    jmp @@dilithium3_test
    
@@kyber768_pass:
    lea rcx, Pass_Str
    call printf
    
@@dilithium3_test:
    ; Run Dilithium-3 test
    lea rcx, Dilithium3_Test_Str
    call printf
    
    call SwarmV29_KAT_Run_Dilithium3
    mov QWORD PTR [Dilithium3_Result], rax
    
    ; Print result
    test rax, rax
    jz @@dilithium3_pass
    
    lea rcx, Fail_Str
    call printf
    jmp @@falcon512_test
    
@@dilithium3_pass:
    lea rcx, Pass_Str
    call printf
    
@@falcon512_test:
    ; Run Falcon-512 test
    lea rcx, Falcon512_Test_Str
    call printf
    
    call SwarmV29_KAT_Run_Falcon512
    mov QWORD PTR [Falcon512_Result], rax
    
    ; Print result
    test rax, rax
    jz @@falcon512_pass
    
    lea rcx, Fail_Str
    call printf
    jmp @@print_summary
    
@@falcon512_pass:
    lea rcx, Pass_Str
    call printf
    
@@print_summary:
    ; Print separator
    lea rcx, Separator
    call printf
    
    ; Get pass/fail counts
    call SwarmV29_KAT_Get_PassCount
    mov QWORD PTR [Total_Pass_Count], rax
    
    call SwarmV29_KAT_Get_FailCount
    mov QWORD PTR [Total_Fail_Count], rax
    
    ; Get max error
    call SwarmV29_KAT_Get_MaxError
    mov QWORD PTR [Max_Error_Value], rax
    
    ; Print max error
    lea rcx, Max_Error_Str
    call printf
    
    mov rax, QWORD PTR [Max_Error_Value]
    ; Convert to string and print (simplified)
    ; In real implementation, use proper number formatting
    
    lea rcx, Newline
    call printf
    
    ; Print pass count
    lea rcx, Pass_Count_Str
    call printf
    
    mov rax, QWORD PTR [Total_Pass_Count]
    ; Convert to string and print (simplified)
    
    lea rcx, Newline
    call printf
    
    ; Print fail count
    lea rcx, Fail_Count_Str
    call printf
    
    mov rax, QWORD PTR [Total_Fail_Count]
    ; Convert to string and print (simplified)
    
    lea rcx, Newline
    call printf
    
    ; Print conclusion
    lea rcx, Conclusion_Str
    call printf
    
    ; Check if all tests passed
    mov rax, QWORD PTR [Total_Fail_Count]
    test rax, rax
    jz @@all_pass
    
    lea rcx, Some_Fail_Str
    call printf
    mov eax, -1
    jmp @@done
    
@@all_pass:
    lea rcx, All_Pass_Str
    call printf
    xor eax, eax
    
@@done:
    SWARMV29_ABI_EPILOG
main ENDP

END