; ============================================================================
; MicroRoslyn_Test.asm - Standalone test harness for MicroRoslyn Syntax Engine
; ============================================================================

OPTION CASEMAP:NONE

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

EXTERN Rawrxd_ParseCSharpSyntax:PROC
EXTERN Rawrxd_GetDiagnosticCount:PROC
EXTERN Rawrxd_GetDiagnostic:PROC

PUBLIC mainCRTStartup

STD_OUTPUT_HANDLE EQU -11

.data

hStdOut QWORD 0
bytesWritten QWORD 0

szHeader BYTE "=========================================================", 13, 10
       BYTE "  MicroRoslyn Syntax Engine - Smoke Test", 13, 10
       BYTE "=========================================================", 13, 10, 0

szTest1 BYTE "[TEST 1] Parsing valid C#...", 13, 10, 0
szTest2 BYTE "[TEST 2] Parsing C# with missing semicolon...", 13, 10, 0
szTest3 BYTE "[TEST 3] Parsing C# with unclosed brace...", 13, 10, 0
szPass  BYTE "[PASS] No diagnostics", 13, 10, 0
szDiag  BYTE "[DIAG] Count: ", 0
szDone  BYTE "[DONE] All tests complete", 13, 10, 0
szCrlf  BYTE 13, 10, 0

; Test code samples
TestCode1 BYTE "class Test { int x; }", 0
TestCode2 BYTE "int x", 0
TestCode3 BYTE "class Test { int x;", 0

NumBuffer BYTE 32 DUP(0)

.code

mainCRTStartup PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Print header
    lea rcx, szHeader
    call TestPrintString
    
    ; Test 1: Valid C#
    lea rcx, szTest1
    call TestPrintString
    lea rcx, TestCode1
    xor rdx, rdx
    call Rawrxd_ParseCSharpSyntax
    call Rawrxd_GetDiagnosticCount
    test rax, rax
    jnz Test1_fail
    lea rcx, szPass
    call TestPrintString
    jmp Test2
    
Test1_fail:
    call PrintDiagnosticCount
    
Test2:
    ; Test 2: Missing semicolon
    lea rcx, szTest2
    call TestPrintString
    lea rcx, TestCode2
    xor rdx, rdx
    call Rawrxd_ParseCSharpSyntax
    call Rawrxd_GetDiagnosticCount
    test rax, rax
    jz Test2_fail
    call PrintDiagnosticCount
    jmp Test3
    
Test2_fail:
    lea rcx, szPass
    call TestPrintString
    
Test3:
    ; Test 3: Unclosed brace
    lea rcx, szTest3
    call TestPrintString
    lea rcx, TestCode3
    xor rdx, rdx
    call Rawrxd_ParseCSharpSyntax
    call Rawrxd_GetDiagnosticCount
    test rax, rax
    jz Test3_fail
    call PrintDiagnosticCount
    jmp Done
    
Test3_fail:
    lea rcx, szPass
    call TestPrintString
    
Done:
    lea rcx, szDone
    call TestPrintString
    
    xor rcx, rcx
    call ExitProcess
    
    add rsp, 40h
    pop rbp
    ret
mainCRTStartup ENDP

; ============================================================================
; TestPrintString - RCX = null-terminated string
; Uses volatile registers R10/R11 to avoid corrupting caller state
; ============================================================================
TestPrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    .ENDPROLOG
    
    mov r10, rcx
    
    ; Calculate length
    xor r11, r11
    mov rax, r10
strlen_loop:
    cmp byte ptr [rax], 0
    je strlen_done
    inc r11
    inc rax
    jmp strlen_loop
strlen_done:
    
    ; WriteFile(hStdOut, buffer, length, &written, NULL)
    mov rcx, hStdOut
    mov rdx, r10
    mov r8, r11
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
    add rsp, 30h
    pop rbp
    ret
TestPrintString ENDP

; ============================================================================
; PrintDiagnosticCount - Prints current diagnostic count as integer
; ============================================================================
PrintDiagnosticCount PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    push rbx
    push r12
    
    lea rcx, szDiag
    call TestPrintString
    
    call Rawrxd_GetDiagnosticCount
    mov r12, rax
    
    ; Convert to string
    lea rbx, NumBuffer + 31
    mov byte ptr [rbx], 0
    dec rbx
    
    test r12, r12
    jnz convert_loop
    mov byte ptr [rbx], '0'
    dec rbx
    jmp print_num
    
convert_loop:
    mov rax, r12
    xor rdx, rdx
    mov r9, 10
    div r9
    add dl, '0'
    mov byte ptr [rbx], dl
    dec rbx
    mov r12, rax
    test r12, r12
    jnz convert_loop
    
print_num:
    inc rbx
    mov rcx, rbx
    call TestPrintString
    
    lea rcx, szCrlf
    call TestPrintString
    
    pop r12
    pop rbx
    add rsp, 40h
    pop rbp
    ret
PrintDiagnosticCount ENDP

END
