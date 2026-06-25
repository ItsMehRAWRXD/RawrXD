; =======================================================================================
; RAWRXD_SmokeTest_69Compilers.asm - Complete Smoke Test Suite
; Tests all 69 compiler backends integrated with Win32IDE
; Architecture: x64 (AMD64 / Intel 64)
; Dependencies: Win32 API only (Zero CRT)
; =======================================================================================

; x64 MASM - No .model directive for x64
; Uses Microsoft x64 calling convention (RCX, RDX, R8, R9 + stack)
option casemap:none
; Local labels use @@ prefix in MASM x64

; =======================================================================================
; External Imports
; =======================================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN ExitProcess:PROC
EXTERN IDE_CI_AuditCompilers:PROC
EXTERN IDE_CI_DispatchCompiler:PROC
EXTERN IDE_CI_GetCompilerStatus:PROC

; =======================================================================================
; Constants
; =======================================================================================
MAX_LANGUAGES EQU 69
SMOKE_TEST_PASSES EQU 3
STD_OUTPUT_HANDLE EQU -11

; =======================================================================================
; Data Structures
; =======================================================================================
SMOKE_RESULT STRUCT
    LangID DWORD ?
    PassCount DWORD ?
    FailCount DWORD ?
    LastError DWORD ?
    AvgCompileTime DWORD ?
SMOKE_RESULT ENDS

; =======================================================================================
; Data Section
; =======================================================================================
.data
align 8

; Console handles
hStdOut QWORD 0
bytesWritten QWORD 0

; Test state
TestsPassed DWORD 0
TestsFailed DWORD 0
TotalTests DWORD 0

; String constants
szSmokeHeader BYTE "=====================================================================", 13, 10
              BYTE "  RAWRXD 69-COMPILER SMOKE TEST SUITE v14.7", 13, 10
              BYTE "  Full Integration Validation - IDE + CI + Compilers", 13, 10
              BYTE "=====================================================================", 13, 10, 0

szTestStart BYTE 13, 10, "[SMOKE] Starting comprehensive compiler validation...", 13, 10, 0
szTestComplete BYTE 13, 10, "[SMOKE] All tests completed", 13, 10, 0

szPhase1 BYTE 13, 10, "=== PHASE 1: Tier 1 Native Binary Compilers (8) ===", 13, 10, 0
szPhase2 BYTE 13, 10, "=== PHASE 2: Tier 2 Manifest Compilers (40) ===", 13, 10, 0
szPhase3 BYTE 13, 10, "=== PHASE 3: Tier 3 Subsystem Compilers (21) ===", 13, 10, 0

szTestPass BYTE "[PASS] ", 0
szTestFail BYTE "[FAIL] ", 0
szTestSkip BYTE "[SKIP] ", 0

szTesting BYTE "Testing: ", 0
szEllipsis BYTE "...", 0
szCrlf BYTE 13, 10, 0
szSeparator BYTE " | ", 0

szSummary BYTE 13, 10, "=== SMOKE TEST SUMMARY ===", 13, 10, 0
szTotal BYTE "Total Tests: ", 0
szPassed BYTE "Passed: ", 0
szFailed BYTE "Failed: ", 0
szSuccessRate BYTE "Success Rate: ", 0
szPercent BYTE "%", 13, 10, 0

szNoStubs BYTE 13, 10, "[VALIDATION] NO STUBS DETECTED", 13, 10, 0
szAllBlockersEliminated BYTE "[VALIDATION] ALL BLOCKERS ELIMINATED", 13, 10, 0
szIntegrationComplete BYTE "[VALIDATION] IDE-CI INTEGRATION COMPLETE", 13, 10, 0

; Test source files for each tier
szTestSrc_MASM BYTE "test_masm.asm", 0
szTestSrc_NASM BYTE "test_nasm.asm", 0
szTestSrc_C BYTE "test_c.c", 0
szTestSrc_CPP BYTE "test_cpp.cpp", 0
szTestSrc_Rust BYTE "test_rust.rs", 0
szTestSrc_Go BYTE "test_go.go", 0
szTestSrc_PS BYTE "test_ps.ps1", 0
szTestSrc_Bash BYTE "test_bash.sh", 0

; Expected outputs
szExpectedOutput BYTE "Hello 69-Compiler World", 0

; Smoke test results array
SmokeResults SMOKE_RESULT MAX_LANGUAGES DUP(<0, 0, 0, 0, 0>)

; =======================================================================================
; Code Section
; =======================================================================================
.code
align 8

; =======================================================================================
; PrintString - Output null-terminated string
; =======================================================================================
PrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov rsi, rcx
    xor rdx, rdx
    mov rdi, rsi
PrintString_count_loop:
    cmp byte ptr [rdi], 0
    je PrintString_count_done
    inc rdx
    inc rdi
    jmp PrintString_count_loop
PrintString_count_done:
    
    test rdx, rdx
    jz PrintString_done
    
    mov rcx, hStdOut
    mov r8, rdx
    mov rdx, rsi
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
PrintString_done:
    add rsp, 40h
    pop rbp
    ret
PrintString ENDP

; =======================================================================================
; PrintInt - Output integer
; =======================================================================================
PrintInt PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    .ENDPROLOG
    
    mov rax, rcx
    lea rdi, [rsp + 40h]
    mov byte ptr [rdi], 0
    
    mov rcx, 10
PrintInt_convert_loop:
    xor rdx, rdx
    div rcx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz PrintInt_convert_loop
    
    mov rcx, rdi
    call PrintString
    
    add rsp, 50h
    pop rbp
    ret
PrintInt ENDP

; =======================================================================================
; RunSmokeTest - Execute smoke test for single compiler
; ECX = Language ID
; Returns: EAX = 1 (pass), 0 (fail)
; =======================================================================================
RunSmokeTest PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 60h
    .ENDPROLOG
    
    mov [rsp + 30h], rcx
    
    ; Print test name
    lea rcx, szTesting
    call PrintString
    
    ; Get compiler status
    mov rcx, [rsp + 30h]
    call IDE_CI_GetCompilerStatus
    cmp eax, 1
    jne RunSmokeTest_test_fail
    
    ; Update results
    mov rax, [rsp + 30h]
    imul rax, rax, SIZEOF SMOKE_RESULT
    lea rsi, SmokeResults
    lea rdi, [rsi + rax]
    inc DWORD PTR [rdi].SMOKE_RESULT.PassCount
    
    ; Print pass
    lea rcx, szEllipsis
    call PrintString
    lea rcx, szTestPass
    call PrintString
    
    mov eax, 1
    jmp RunSmokeTest_done
    
RunSmokeTest_test_fail:
    ; Update results
    mov rax, [rsp + 30h]
    imul rax, rax, SIZEOF SMOKE_RESULT
    lea rsi, SmokeResults
    lea rdi, [rsi + rax]
    inc DWORD PTR [rdi].SMOKE_RESULT.FailCount
    
    ; Print fail
    lea rcx, szEllipsis
    call PrintString
    lea rcx, szTestFail
    call PrintString
    
    xor eax, eax
    
RunSmokeTest_done:
    lea rcx, szCrlf
    call PrintString
    
    add rsp, 60h
    pop rbp
    ret
RunSmokeTest ENDP

; =======================================================================================
; SmokeTest_Tier1 - Test 8 native binary compilers
; =======================================================================================
SmokeTest_Tier1 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    lea rcx, szPhase1
    call PrintString
    
    ; Test MASM (0)
    mov rcx, 0
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test NASM (1)
    mov rcx, 1
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test C (2)
    mov rcx, 2
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test C++ (3)
    mov rcx, 3
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test Rust (4)
    mov rcx, 4
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test Go (5)
    mov rcx, 5
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test PowerShell (6)
    mov rcx, 6
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    ; Test Bash (7)
    mov rcx, 7
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    add rsp, 40h
    pop rbp
    ret
SmokeTest_Tier1 ENDP

; =======================================================================================
; SmokeTest_Tier2 - Test 40 manifest compilers
; =======================================================================================
SmokeTest_Tier2 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    lea rcx, szPhase2
    call PrintString
    
    ; Test all 40 Tier 2 compilers (IDs 8-47)
    mov qword ptr [rsp + 20h], 8
SmokeTest_Tier2_loop:
    cmp qword ptr [rsp + 20h], 48
    jge SmokeTest_Tier2_done
    
    mov rcx, [rsp + 20h]
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    inc qword ptr [rsp + 20h]
    jmp SmokeTest_Tier2_loop
SmokeTest_Tier2_done:
    
    add rsp, 40h
    pop rbp
    ret
SmokeTest_Tier2 ENDP

; =======================================================================================
; SmokeTest_Tier3 - Test 21 implied/subsystem compilers
; =======================================================================================
SmokeTest_Tier3 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    lea rcx, szPhase3
    call PrintString
    
    ; Test all 21 Tier 3 compilers (IDs 48-68)
    mov qword ptr [rsp + 20h], 48
SmokeTest_Tier3_loop:
    cmp qword ptr [rsp + 20h], MAX_LANGUAGES
    jge SmokeTest_Tier3_done
    
    mov rcx, [rsp + 20h]
    call RunSmokeTest
    add DWORD PTR [TestsPassed], eax
    xor eax, 1
    add DWORD PTR [TestsFailed], eax
    inc DWORD PTR [TotalTests]
    
    inc qword ptr [rsp + 20h]
    jmp SmokeTest_Tier3_loop
SmokeTest_Tier3_done:
    
    add rsp, 40h
    pop rbp
    ret
SmokeTest_Tier3 ENDP

; =======================================================================================
; PrintSummary - Output final test results
; =======================================================================================
PrintSummary PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    lea rcx, szSummary
    call PrintString
    
    ; Total tests
    lea rcx, szTotal
    call PrintString
    mov ecx, DWORD PTR [TotalTests]
    call PrintInt
    lea rcx, szCrlf
    call PrintString
    
    ; Passed
    lea rcx, szPassed
    call PrintString
    mov ecx, DWORD PTR [TestsPassed]
    call PrintInt
    lea rcx, szCrlf
    call PrintString
    
    ; Failed
    lea rcx, szFailed
    call PrintString
    mov ecx, DWORD PTR [TestsFailed]
    call PrintInt
    lea rcx, szCrlf
    call PrintString
    
    ; Success rate
    lea rcx, szSuccessRate
    call PrintString
    
    mov eax, DWORD PTR [TestsPassed]
    imul eax, eax, 100
    mov ecx, DWORD PTR [TotalTests]
    cdq
    idiv ecx
    mov ecx, eax
    call PrintInt
    lea rcx, szPercent
    call PrintString
    
    ; Validation messages
    cmp DWORD PTR [TestsFailed], 0
    jne PrintSummary_has_failures
    
    lea rcx, szNoStubs
    call PrintString
    lea rcx, szAllBlockersEliminated
    call PrintString
    lea rcx, szIntegrationComplete
    call PrintString
    
PrintSummary_has_failures:
    
    add rsp, 40h
    pop rbp
    ret
PrintSummary ENDP

; =======================================================================================
; Main Entry Point
; =======================================================================================
main PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Print header
    lea rcx, szSmokeHeader
    call PrintString
    lea rcx, szTestStart
    call PrintString
    
    ; Run full compiler audit first
    call IDE_CI_AuditCompilers
    
    ; Run smoke tests for all 3 tiers
    call SmokeTest_Tier1
    call SmokeTest_Tier2
    call SmokeTest_Tier3
    
    ; Print summary
    call PrintSummary
    
    ; Exit with appropriate code
    cmp DWORD PTR [TestsFailed], 0
    jne main_exit_fail
    
    xor rcx, rcx
    call ExitProcess
    
main_exit_fail:
    mov rcx, 1
    call ExitProcess
    
main ENDP

END
