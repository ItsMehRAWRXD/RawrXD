; =============================================================================
; RawrXD_IDE_Validator.asm - IDE Validation via Debugger Integration
; Uses RawrXD_MinimalDebugger to verify IDE correctness at runtime
; =============================================================================
option casemap:none

EXTERN WaitForDebugEvent:PROC
EXTERN ContinueDebugEvent:PROC
EXTERN DebugActiveProcess:PROC
EXTERN DebugActiveProcessStop:PROC
EXTERN GetThreadContext:PROC
EXTERN SetThreadContext:PROC
EXTERN ReadProcessMemory:PROC
EXTERN WriteProcessMemory:PROC
EXTERN VirtualQueryEx:PROC
EXTERN VirtualProtectEx:PROC
EXTERN OpenProcess:PROC
EXTERN OpenThread:PROC
EXTERN CloseHandle:PROC
EXTERN CreateProcessA:PROC
EXTERN GetModuleHandleA:PROC
EXTERN GetProcAddress:PROC
EXTERN GetLastError:PROC
EXTERN ExitProcess:PROC
EXTERN WriteConsoleA:PROC
EXTERN GetStdHandle:PROC

; Constants
STD_OUTPUT_HANDLE           EQU -11
INFINITE                    EQU 0FFFFFFFFh
PROCESS_ALL_ACCESS          EQU 1F0FFFh
THREAD_ALL_ACCESS           EQU 1F03FFh
DBG_CONTINUE                EQU 00002h
EXCEPTION_DEBUG_EVENT       EQU 1
CREATE_PROCESS_DEBUG_EVENT  EQU 3
EXIT_PROCESS_DEBUG_EVENT    EQU 5
EXCEPTION_BREAKPOINT        EQU 80000003h
EXCEPTION_SINGLE_STEP       EQU 80000004h
EXCEPTION_ACCESS_VIOLATION  EQU 0C0000005h
EXCEPTION_STACK_OVERFLOW    EQU 0C00000FDh
CONTEXT_FULL                EQU 00010001h
CONTEXT_DEBUG_REGISTERS     EQU 00010010h
MEM_COMMIT                  EQU 1000h
PAGE_EXECUTE_READWRITE      EQU 40h

; Structures
DEBUG_EVENT STRUCT
    dwDebugEventCode    DD ?
    dwProcessId         DD ?
    dwThreadId          DD ?
    u                   DB 164 DUP(?)
DEBUG_EVENT ENDS

CONTEXT STRUCT
    P1Home              DQ ?
    P2Home              DQ ?
    P3Home              DQ ?
    P4Home              DQ ?
    ContextFlags        DD ?
    MxCsr               DD ?
    SegCs               DW ?
    SegDs                DW ?
    SegEs                DW ?
    SegFs                DW ?
    SegGs                DW ?
    SegSs                DW ?
    EFlags               DD ?
    Dr0_                 DQ ?
    Dr1_                 DQ ?
    Dr2_                 DQ ?
    Dr3_                 DQ ?
    Dr6_                 DQ ?
    Dr7_                 DQ ?
    Rax_                 DQ ?
    Rcx_                 DQ ?
    Rdx_                 DQ ?
    Rbx_                 DQ ?
    Rsp_                 DQ ?
    Rbp_                 DQ ?
    Rsi_                 DQ ?
    Rdi_                 DQ ?
    R8_                  DQ ?
    R9_                  DQ ?
    R10_                 DQ ?
    R11_                 DQ ?
    R12_                 DQ ?
    R13_                 DQ ?
    R14_                 DQ ?
    R15_                 DQ ?
    Rip_                 DQ ?
    FltSave              DB 512 DUP(?)
CONTEXT ENDS

MEMORY_BASIC_INFORMATION STRUCT
    BaseAddress         DQ ?
    AllocationBase      DQ ?
    AllocationProtect   DD ?
    __pad1              DD ?
    RegionSize          DQ ?
    State               DD ?
    Protect             DD ?
    MemType             DD ?
    __pad2              DD ?
MEMORY_BASIC_INFORMATION ENDS

; Validation results
VALIDATION_SUCCESS           EQU 0
VALIDATION_MEMORY_ERROR      EQU 1
VALIDATION_STACK_ERROR       EQU 2
VALIDATION_HEAP_ERROR        EQU 3
VALIDATION_ABI_ERROR         EQU 4
VALIDATION_SEH_ERROR         EQU 5
VALIDATION_ENTRY_ERROR       EQU 6

.data
g_hStdOut           DQ ?
g_hProcess          DQ ?
g_hThread           DQ ?
g_targetPid         DD ?
g_continueStatus    DD DBG_CONTINUE
g_validationResult  DD 0
g_errorCount        DD 0
g_passCount         DD 0

; Validation messages
szPass              DB "[PASS] ", 0
szFail              DB "[FAIL] ", 0
szMemTest           DB "Memory integrity check", 13, 10, 0
szStackTest         DB "Stack alignment check", 13, 10, 0
szHeapTest          DB "Heap validation", 13, 10, 0
szABITest           DB "Calling convention ABI", 13, 10, 0
szSEHTest           DB "SEH frame integrity", 13, 10, 0
szEntryTest         DB "Entry point validation", 13, 10, 0
szRIPTest           DB "Instruction pointer valid", 13, 10, 0
szRegTest           DB "Register state valid", 13, 10, 0
szDone              DB "Validation complete. Errors: ", 0
szNewLine           DB 13, 10, 0

.code

; =============================================================================
; WriteOutput - Write string to console
; RCX = string pointer
; =============================================================================
WriteOutput PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov rbx, rcx
    
    ; Calculate length
    xor edx, edx
    lea rax, [rbx]
@@len:
    cmp byte ptr [rax], 0
    je @@write
    inc edx
    inc rax
    jmp @@len
    
@@write:
    mov rcx, [g_hStdOut]
    mov r8, rdx
    mov rdx, rbx
    lea r9, [rsp+20h]
    mov qword ptr [rsp+20h], 0
    call WriteConsoleA
    
    add rsp, 28h
    pop rbx
    ret
WriteOutput ENDP

; =============================================================================
; ValidateMemoryIntegrity - Check target process memory
; RCX = hProcess
; Returns: RAX = 0 success, non-zero error
; =============================================================================
ValidateMemoryIntegrity PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 58h
    .allocstack 58h
    .endprolog
    
    mov rbx, rcx
    
    ; Check if process handle is valid
    test rbx, rbx
    jz @@fail
    
    ; Query base address (PE header)
    lea rax, [rsp+20h]
    mov qword ptr [rax], 0        ; BaseAddress
    mov qword ptr [rax+8], 0      ; AllocationBase
    
    mov rcx, rbx
    xor rdx, rdx                   ; NULL = query from base
    lea r8, [rsp+20h]
    mov r9, 38h
    call VirtualQueryEx
    
    test rax, rax
    jz @@fail
    
    ; Verify MEM_COMMIT
    mov eax, [rsp+28h]            ; State
    cmp eax, MEM_COMMIT
    jne @@fail
    
    ; Verify executable
    mov eax, [rsp+30h]             ; Protect
    test eax, PAGE_EXECUTE_READWRITE
    jz @@fail
    
    xor rax, rax
    jmp @@done
    
@@fail:
    mov rax, VALIDATION_MEMORY_ERROR
    
@@done:
    add rsp, 58h
    pop rbx
    ret
ValidateMemoryIntegrity ENDP

; =============================================================================
; ValidateStackAlignment - Verify RSP is 16-byte aligned
; RCX = hThread
; Returns: RAX = 0 success, non-zero error
; =============================================================================
ValidateStackAlignment PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 50h
    .allocstack 50h
    .endprolog
    
    mov rbx, rcx
    
    ; Get thread context
    lea rcx, [rsp+20h]
    mov dword ptr [rcx+30h], CONTEXT_FULL
    mov rcx, rbx
    call GetThreadContext
    
    test rax, rax
    jz @@fail
    
    ; Check RSP alignment (must be 16-byte aligned after call)
    mov rax, [rsp+58h]            ; CONTEXT.Rsp
    test al, 0Fh
    jnz @@fail
    
    ; Check RSP is in valid range (not NULL, not kernel space)
    test rax, rax
    jz @@fail
    mov r8, 7FFFFFFF0000h
    cmp rax, r8
    jae @@fail
    
    xor rax, rax
    jmp @@done
    
@@fail:
    mov rax, VALIDATION_STACK_ERROR
    
@@done:
    add rsp, 50h
    pop rbx
    ret
ValidateStackAlignment ENDP

; =============================================================================
; ValidateABI - Verify calling convention compliance
; RCX = hProcess, RDX = hThread
; Returns: RAX = 0 success, non-zero error
; =============================================================================
ValidateABI PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 48h
    .allocstack 48h
    .endprolog
    
    mov rbx, rcx
    mov rsi, rdx
    
    ; Get thread context
    lea rcx, [rsp+20h]
    mov dword ptr [rcx+30h], CONTEXT_FULL
    mov rcx, rsi
    call GetThreadContext
    
    test rax, rax
    jz @@fail
    
    ; Verify non-volatile registers are preserved
    ; RBX, RBP, RSI, RDI, R12-R15 should be valid pointers or zero
    
    mov rax, [rsp+48h]            ; CONTEXT.Rbx
    test rax, rax
    jnz @@check_rbx
    mov rax, [rsp+50h]            ; CONTEXT.Rbp
    test rax, rax
    jnz @@check_rbp
    
    ; Both can be zero (valid)
    jmp @@check_r12
    
@@check_rbx:
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@check_rbp:
    mov rax, [rsp+50h]
    test rax, rax
    jz @@check_r12
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@check_r12:
    mov rax, [rsp+80h]            ; CONTEXT.R12
    test rax, rax
    jz @@check_r13
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@check_r13:
    mov rax, [rsp+88h]            ; CONTEXT.R13
    test rax, rax
    jz @@check_r14
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@check_r14:
    mov rax, [rsp+90h]            ; CONTEXT.R14
    test rax, rax
    jz @@check_r15
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@check_r15:
    mov rax, [rsp+98h]            ; CONTEXT.R15
    test rax, rax
    jz @@success
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@success:
    xor rax, rax
    jmp @@done
    
@@fail:
    mov rax, VALIDATION_ABI_ERROR
    
@@done:
    add rsp, 48h
    pop rsi
    pop rbx
    ret
ValidateABI ENDP

; =============================================================================
; ValidateSEH - Verify SEH chain integrity
; RCX = hProcess, RDX = RSP value
; Returns: RAX = 0 success, non-zero error
; =============================================================================
ValidateSEH PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 50h
    .allocstack 50h
    .endprolog
    
    mov rbx, rcx
    mov rsi, rdx
    
    ; Read TEB.NtTib.ExceptionList (fs:[0])
    ; For x64, this is at gs:[0]
    ; We need to read the EXCEPTION_REGISTRATION from the stack
    
    ; Read first SEH frame at [RSP]
    mov rcx, rbx
    mov rdx, rsi
    lea r8, [rsp+20h]
    mov r9, 8
    mov qword ptr [rsp+28h], 0
    call ReadProcessMemory
    
    test rax, rax
    jz @@fail
    
    ; First 8 bytes should be next handler (or -1 for end)
    mov rax, [rsp+20h]
    
    ; -1 means end of chain (valid)
    cmp rax, -1
    je @@success
    
    ; Otherwise should be valid stack address
    test rax, rax
    jz @@fail
    mov r8, 7FFFFFFF0000h; cmp rax, r8
    jae @@fail
    
@@success:
    xor rax, rax
    jmp @@done
    
@@fail:
    mov rax, VALIDATION_SEH_ERROR
    
@@done:
    add rsp, 50h
    pop rsi
    pop rbx
    ret
ValidateSEH ENDP

; =============================================================================
; ValidateEntryPoint - Verify RIP points to valid code
; RCX = hProcess, RDX = RIP value
; Returns: RAX = 0 success, non-zero error
; =============================================================================
ValidateEntryPoint PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 48h
    .allocstack 48h
    .endprolog
    
    mov rbx, rcx
    mov rsi, rdx
    
    ; Query memory at RIP
    lea rax, [rsp+20h]
    mov rcx, rbx
    mov rdx, rsi
    lea r8, [rsp+20h]
    mov r9, 38h
    call VirtualQueryEx
    
    test rax, rax
    jz @@fail
    
    ; Must be committed
    mov eax, [rsp+28h]
    cmp eax, MEM_COMMIT
    jne @@fail
    
    ; Must be executable
    mov eax, [rsp+30h]
    test eax, PAGE_EXECUTE_READWRITE
    jnz @@success
    
    ; Also check for PAGE_EXECUTE_READ
    test eax, 20h
    jnz @@success
    
    jmp @@fail
    
@@success:
    xor rax, rax
    jmp @@done
    
@@fail:
    mov rax, VALIDATION_ENTRY_ERROR
    
@@done:
    add rsp, 48h
    pop rsi
    pop rbx
    ret
ValidateEntryPoint ENDP

; =============================================================================
; IDEValidatorMain - Main validation entry point
; RCX = target PID
; =============================================================================
IDEValidatorRawrXD_IDE_Validator_Main PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 0B8h
    .allocstack 0B8h
    .endprolog
    
    mov [g_targetPid], ecx
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [g_hStdOut], rax
    
    ; Attach to process
    mov ecx, [g_targetPid]
    call DebugActiveProcess
    test rax, rax
    jz @@exit
    
@@event_loop:
    ; Wait for debug event
    lea rcx, [rsp+20h]
    mov edx, INFINITE
    call WaitForDebugEvent
    
    test rax, rax
    jz @@exit
    
    ; Dispatch
    mov eax, [rsp+20h]
    
    cmp eax, CREATE_PROCESS_DEBUG_EVENT
    je @@on_create_process
    
    cmp eax, EXCEPTION_DEBUG_EVENT
    je @@on_exception
    
    cmp eax, EXIT_PROCESS_DEBUG_EVENT
    je @@on_exit
    
    jmp @@continue
    
@@on_create_process:
    ; Store handles
    mov rax, [rsp+28h]
    mov [g_hProcess], rax
    mov rax, [rsp+30h]
    mov [g_hThread], rax
    
    ; Run validations
    lea rcx, szMemTest
    call WriteOutput
    
    mov rcx, [g_hProcess]
    call ValidateMemoryIntegrity
    test rax, rax
    jnz @@validation_failed
    inc [g_passCount]
    jmp @@test_stack
    
@@validation_failed:
    inc [g_errorCount]
    lea rcx, szFail
    call WriteOutput
    
@@test_stack:
    lea rcx, szStackTest
    call WriteOutput
    
    mov rcx, [g_hThread]
    call ValidateStackAlignment
    test rax, rax
    jnz @@stack_failed
    inc [g_passCount]
    jmp @@test_abi
    
@@stack_failed:
    inc [g_errorCount]
    lea rcx, szFail
    call WriteOutput
    
@@test_abi:
    lea rcx, szABITest
    call WriteOutput
    
    mov rcx, [g_hProcess]
    mov rdx, [g_hThread]
    call ValidateABI
    test rax, rax
    jnz @@abi_failed
    inc [g_passCount]
    jmp @@test_seh
    
@@abi_failed:
    inc [g_errorCount]
    lea rcx, szFail
    call WriteOutput
    
@@test_seh:
    lea rcx, szSEHTest
    call WriteOutput
    
    mov rcx, [g_hProcess]
    mov rdx, [rsp+58h]            ; RSP from context
    call ValidateSEH
    test rax, rax
    jnz @@seh_failed
    inc [g_passCount]
    jmp @@test_entry
    
@@seh_failed:
    inc [g_errorCount]
    lea rcx, szFail
    call WriteOutput
    
@@test_entry:
    lea rcx, szEntryTest
    call WriteOutput
    
    mov rcx, [g_hProcess]
    mov rdx, [rsp+70h]            ; RIP from context
    call ValidateEntryPoint
    test rax, rax
    jnz @@entry_failed
    inc [g_passCount]
    jmp @@continue
    
@@entry_failed:
    inc [g_errorCount]
    lea rcx, szFail
    call WriteOutput
    
    jmp @@continue
    
@@on_exception:
    ; Check exception code
    mov eax, [rsp+24h]
    
    cmp eax, EXCEPTION_BREAKPOINT
    je @@on_breakpoint
    
    cmp eax, EXCEPTION_ACCESS_VIOLATION
    je @@on_access_violation
    
    cmp eax, EXCEPTION_STACK_OVERFLOW
    je @@on_stack_overflow
    
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@on_breakpoint:
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@on_access_violation:
    inc [g_errorCount]
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@on_stack_overflow:
    inc [g_errorCount]
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@on_exit:
    ; Print summary
    lea rcx, szDone
    call WriteOutput
    
    mov eax, [g_errorCount]
    add al, '0'
    mov byte ptr [rsp+20h], al
    mov byte ptr [rsp+21h], 13
    mov byte ptr [rsp+22h], 10
    mov byte ptr [rsp+23h], 0
    
    mov rcx, [g_hStdOut]
    mov r8d, 3
    lea rdx, [rsp+20h]
    lea r9, [rsp+28h]
    mov qword ptr [rsp+28h], 0
    call WriteConsoleA
    
    jmp @@exit
    
@@continue:
    mov ecx, [rsp+24h]
    mov edx, [rsp+28h]
    mov r8d, [g_continueStatus]
    call ContinueDebugEvent
    jmp @@event_loop
    
@@exit:
    mov ecx, [g_targetPid]
    call DebugActiveProcessStop
    
    mov eax, [g_errorCount]
    add rsp, 0B8h
    pop rdi
    pop rsi
    pop rbx
    ret
IDEValidatorRawrXD_IDE_Validator_Main ENDP

END



