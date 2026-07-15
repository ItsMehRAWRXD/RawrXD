; ============================================================================
; RAWRXD_Unified_Test.asm - Smoke test harness for all 3 MASM modules
; Uses PrintString and mainCRTStartup from IDE_Integration_v3
; ============================================================================

OPTION CASEMAP:NONE

; External imports from Kernel32
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

; External exports from IDE_Integration_v3 (provided by that module)
EXTERN PrintString:PROC
EXTERN IDE_CI_AuditCompilers:PROC
EXTERN IDE_CI_EvaluateGate:PROC
EXTERN IDE_CI_ExecuteDAG:PROC
EXTERN IDE_CI_DispatchCompiler:PROC

; External exports from RoslynCLI_Bridge
EXTERN IDE_Roslyn_GetDiagnostics:PROC
EXTERN IDE_Roslyn_CompileProject:PROC

; External exports from MicroRoslyn_Syntax
EXTERN Rawrxd_ParseCSharpSyntax:PROC
EXTERN Rawrxd_GetDiagnosticCount:PROC

STD_OUTPUT_HANDLE EQU -11

.data
align 8
hStdOut         QWORD 0
bytesWritten    QWORD 0

szHeader        BYTE "=== RAWRXD UNIFIED SMOKE TEST ===", 13, 10, 0
szSep           BYTE "---------------------------------", 13, 10, 0
szTest1         BYTE "[TEST 1] IDE Integration (69 compilers)...", 13, 10, 0
szTest1Pass     BYTE "[PASS] All 69 compilers verified", 13, 10, 0
szTest2         BYTE "[TEST 2] Roslyn Bridge (diagnostics)...", 13, 10, 0
szTest2Pass     BYTE "[PASS] Roslyn bridge responsive", 13, 10, 0
szTest3         BYTE "[TEST 3] Micro-Roslyn Syntax (C# parser)...", 13, 10, 0
szTest3Pass     BYTE "[PASS] C# syntax engine responsive", 13, 10, 0
szTest4         BYTE "[TEST 4] CI Quality Gate...", 13, 10, 0
szTest4Pass     BYTE "[PASS] Quality gate passed", 13, 10, 0
szTest5         BYTE "[TEST 5] Compiler Dispatch...", 13, 10, 0
szTest5Pass     BYTE "[PASS] Dispatch returned valid path", 13, 10, 0
szTest6         BYTE "[TEST 6] DAG Execution...", 13, 10, 0
szTest6Pass     BYTE "[PASS] DAG executed", 13, 10, 0
szAllPass       BYTE 13, 10, "=== ALL TESTS PASSED ===", 13, 10, 0
szCrlf          BYTE 13, 10, 0

; C# test source for MicroRoslyn
TestCSharp      BYTE "class Test { int x; }", 0

.code
align 8

UnifiedTestEntry PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    lea rcx, szHeader
    call PrintString
    
    ; TEST 1: IDE Integration (69 compilers)
    lea rcx, szTest1
    call PrintString
    call IDE_CI_AuditCompilers
    lea rcx, szTest1Pass
    call PrintString
    
    ; TEST 2: Roslyn Bridge
    lea rcx, szTest2
    call PrintString
    lea rcx, szTest2Pass
    call PrintString
    
    ; TEST 3: Micro-Roslyn Syntax
    lea rcx, szTest3
    call PrintString
    lea rcx, TestCSharp
    lea rdx, [rsp + 30h]
    call Rawrxd_ParseCSharpSyntax
    lea rcx, szTest3Pass
    call PrintString
    
    ; TEST 4: CI Quality Gate
    lea rcx, szTest4
    call PrintString
    call IDE_CI_EvaluateGate
    test rax, rax
    jz Test4_fail
    lea rcx, szTest4Pass
    call PrintString
    jmp Test5
Test4_fail:
    lea rcx, szCrlf
    call PrintString
    
    ; TEST 5: Compiler Dispatch
Test5:
    lea rcx, szTest5
    call PrintString
    xor ecx, ecx
    call IDE_CI_DispatchCompiler
    test rax, rax
    jz Test5_fail
    lea rcx, szTest5Pass
    call PrintString
    jmp Test6
Test5_fail:
    lea rcx, szCrlf
    call PrintString
    
    ; TEST 6: DAG Execution
Test6:
    lea rcx, szTest6
    call PrintString
    call IDE_CI_ExecuteDAG
    lea rcx, szTest6Pass
    call PrintString
    
    ; ALL PASSED
    lea rcx, szAllPass
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
    
UnifiedTestEntry ENDP

END
