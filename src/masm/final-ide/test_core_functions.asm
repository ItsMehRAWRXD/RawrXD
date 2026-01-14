; test_core_functions.asm - Test core MASM functions
; Simple test program to verify memory management, logging, and orchestration

option casemap:none

.code

; External functions to test
EXTERN console_log:PROC
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN ai_orchestration_coordinator_init:PROC
EXTERN autonomous_task_schedule:PROC
EXTERN ExitProcess:PROC

.data
szTestStart     BYTE "=== RawrXD Core Function Test ===", 0
szTestMemory    BYTE "Testing memory allocation...", 0
szTestOrch      BYTE "Testing orchestration...", 0
szTestTask      BYTE "Testing task scheduling...", 0
szTestComplete  BYTE "All tests completed successfully!", 0
szTestFailed    BYTE "Test failed!", 0
szTestGoal      BYTE "Test autonomous task", 0

.code

; Test entry point
PUBLIC test_main
test_main PROC
    sub rsp, 40
    
    ; Test 1: Console logging
    lea rcx, szTestStart
    call console_log
    
    ; Test 2: Memory allocation
    lea rcx, szTestMemory
    call console_log
    
    mov rcx, 1024           ; Allocate 1KB
    mov rdx, 16             ; 16-byte alignment
    call asm_malloc
    test rax, rax
    jz test_failed
    
    ; Free the memory
    mov rcx, rax
    call asm_free
    
    ; Test 3: Orchestration init
    lea rcx, szTestOrch
    call console_log
    
    call ai_orchestration_coordinator_init
    test eax, eax
    jz test_failed
    
    ; Test 4: Task scheduling
    lea rcx, szTestTask
    call console_log
    
    lea rcx, szTestGoal     ; goal
    mov edx, 5              ; priority
    mov r8b, 1              ; auto-retry
    call autonomous_task_schedule
    
    ; All tests passed
    lea rcx, szTestComplete
    call console_log
    
    xor ecx, ecx            ; Exit code 0
    call ExitProcess
    
test_failed:
    lea rcx, szTestFailed
    call console_log
    
    mov ecx, 1              ; Exit code 1
    call ExitProcess
    
test_main ENDP

; Entry point
PUBLIC _start
_start PROC
    call test_main
    ret
_start ENDP

END




