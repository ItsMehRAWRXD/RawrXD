; ============================================================================
; RoslynCLI_Test.asm - Standalone test harness for Roslyn CLI Bridge
; ============================================================================

OPTION CASEMAP:NONE

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

EXTERN IDE_Roslyn_InvokeCompiler:PROC
EXTERN IDE_Roslyn_ParseErrorOutput:PROC
EXTERN IDE_Roslyn_GetDiagnostics:PROC
EXTERN IDE_Roslyn_CompileProject:PROC

PUBLIC mainCRTStartup

STD_OUTPUT_HANDLE EQU -11

.data

hStdOut QWORD 0
bytesWritten QWORD 0
DiagPtr QWORD 0
DiagCount DWORD 0

szHeader BYTE "=========================================================", 13, 10
       BYTE "  Roslyn CLI Bridge - Smoke Test", 13, 10
       BYTE "=========================================================", 13, 10, 0

szTest1 BYTE "[TEST 1] Compiler invocation structure...", 13, 10, 0
szTest2 BYTE "[TEST 2] Error parser structure...", 13, 10, 0
szTest3 BYTE "[TEST 3] Diagnostic getter structure...", 13, 10, 0
szTest4 BYTE "[TEST 4] Project compiler structure...", 13, 10, 0
szPass  BYTE "[PASS] Function exported and callable", 13, 10, 0
szDone  BYTE "[DONE] All tests complete", 13, 10, 0
szCrlf  BYTE 13, 10, 0
szEmpty BYTE 0
szDummySource BYTE "test.cs", 0
szDummyOutput BYTE "test.exe", 0
szDummyError  BYTE "test.cs(1,1): error CS0000: test", 0

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
    
    ; Test 1: InvokeCompiler
    lea rcx, szTest1
    call TestPrintString
    lea rcx, szDummySource
    lea rdx, szDummyOutput
    call IDE_Roslyn_InvokeCompiler
    lea rcx, szPass
    call TestPrintString
    
    ; Test 2: ParseErrorOutput
    lea rcx, szTest2
    call TestPrintString
    lea rcx, szDummyError
    call IDE_Roslyn_ParseErrorOutput
    lea rcx, szPass
    call TestPrintString
    
    ; Test 3: GetDiagnostics
    lea rcx, szTest3
    call TestPrintString
    lea rcx, DiagPtr
    lea rdx, DiagCount
    call IDE_Roslyn_GetDiagnostics
    lea rcx, szPass
    call TestPrintString
    
    ; Test 4: CompileProject
    lea rcx, szTest4
    call TestPrintString
    lea rcx, szDummySource
    xor rdx, rdx
    call IDE_Roslyn_CompileProject
    lea rcx, szPass
    call TestPrintString
    
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

END
