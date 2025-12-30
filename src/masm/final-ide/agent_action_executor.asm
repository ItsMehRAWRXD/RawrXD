;==========================================================================
; agent_action_executor.asm - Pure MASM Agentic Action Executor
; ==========================================================================
; Replaces action_executor.cpp.
; Executes file edits, searches, builds, and tests.
;==========================================================================

option casemap:none

include windows.inc

;==========================================================================
; EXTERNAL DECLARATIONS
;==========================================================================
EXTERN CreateProcessA:PROC
EXTERN WaitForSingleObject:PROC
EXTERN CloseHandle:PROC
EXTERN agent_self_patch_add_kernel:PROC
EXTERN console_log:PROC
EXTERN GetTickCount64:PROC

;==========================================================================
; DATA SECTION
;==========================================================================
.data
    szExecInit          BYTE "ActionExecutor: Initializing MASM execution engine...", 0
    szExecInitOk        BYTE "ActionExecutor: Initialized", 0
    szExecStart         BYTE "ActionExecutor: Executing task %d (type=%d)", 0
    szExecCmd           BYTE "ActionExecutor: Command: %s", 0
    szExecDone          BYTE "ActionExecutor: Task %d completed in %d ms (status=%d)", 0
    szExecFailStart     BYTE "ActionExecutor: Failed to start task %d (err=%d)", 0
    szExecDoneAll       BYTE "ActionExecutor: Completed %d tasks", 0
    szNoTasks           BYTE "ActionExecutor: No tasks to execute", 0
    szBuildDefaultCmd   BYTE "cmd.exe /C cmake --build . --config Release", 0
    szTestDefaultCmd    BYTE "cmd.exe /C ctest --output-on-failure", 0
    
    ; Action types
    ACTION_FILE_EDIT    EQU 1
    ACTION_SEARCH       EQU 2
    ACTION_BUILD        EQU 3
    ACTION_TEST         EQU 4
    ACTION_GIT          EQU 5

    ; Task types (must match planner defs)
    TASK_TYPE_BUILD             EQU 0
    TASK_TYPE_TEST              EQU 1
    TASK_TYPE_HOTPATCH          EQU 2
    TASK_TYPE_EXECUTE           EQU 3
    TASK_TYPE_HOTFIX            EQU 4
    TASK_TYPE_ROLLBACK          EQU 5
    TASK_TYPE_VALIDATE          EQU 6
    TASK_TYPE_OPTIMIZE          EQU 7

    ; TASK/PLAN structure offsets (mirror planner)
    EXECUTION_PLAN_task_count       EQU 0
    EXECUTION_PLAN_tasks_ptr        EQU 8
    TASK_task_id                    EQU 0
    TASK_task_type                  EQU 4
    TASK_command                    EQU 8
    TASK_command_length             EQU 16

.code

;==========================================================================
; agent_action_executor_init() -> eax (1=success)
;==========================================================================
PUBLIC agent_action_executor_init
agent_action_executor_init PROC
    sub rsp, 32
    lea rcx, szExecInitOk
    call console_log
    mov eax, 1
    add rsp, 32
    ret
agent_action_executor_init ENDP

;==========================================================================
; agent_action_execute(action_ptr: rcx) -> rax (bool)
;==========================================================================
PUBLIC agent_action_execute
agent_action_execute PROC
    push rbx
    sub rsp, 32
    
    mov rbx, rcx        ; rbx = action
    
    ; 1. Route based on type
    mov eax, [rbx]      ; type
    
    cmp eax, ACTION_FILE_EDIT
    je file_edit
    cmp eax, ACTION_BUILD
    je run_build
    
    ; ...
    
    jmp exec_done

file_edit:
    ; call agent_handle_file_edit
    jmp exec_done

run_build:
    call agent_action_run_build
    jmp exec_done

exec_done:
    add rsp, 32
    pop rbx

agent_action_execute ENDP

;==========================================================================
; Helper: run_command(cmd_ptr: rcx, timeout_ms: rdx) -> rax (status BOOL)
;==========================================================================
run_command PROC
    ; rcx = lpCommandLine, rdx = timeout_ms
    push rbx

    push rsi
    push rdi
    sub rsp, 176                ; space for locals

    ; Locals layout (stack grows down):
    ; [rsp+0]..[rsp+31]  shadow space + align
    ; [rsp+32]           bInheritHandles (QWORD)
    ; [rsp+40]           dwCreationFlags (QWORD)
    ; [rsp+48]           lpEnvironment (QWORD)
    ; [rsp+56]           lpCurrentDirectory (QWORD)
    ; [rsp+64]           STARTUPINFOA (size 104 bytes)
    ; [rsp+168]          PROCESS_INFORMATION (size 32 bytes)

    ; Zero STARTUPINFOA and PROCESS_INFORMATION
    lea rbx, [rsp+64]
    mov rsi, 104
zero_si:
    mov BYTE PTR [rbx], 0
    inc rbx
    dec rsi
    jnz zero_si

    lea rbx, [rsp+168]
    mov rsi, 32
zero_pi:
    mov BYTE PTR [rbx], 0
    inc rbx
    dec rsi
    jnz zero_pi

    ; Set STARTUPINFOA.cb
    mov DWORD PTR [rsp+64], 104

    ; Prepare CreateProcessA parameters
    xor r8, r8                  ; lpProcessAttributes = NULL
    xor r9, r9                  ; lpThreadAttributes = NULL
    mov qword ptr [rsp+32], 0   ; bInheritHandles = FALSE
    mov qword ptr [rsp+40], 0   ; dwCreationFlags = 0
    mov qword ptr [rsp+48], 0   ; lpEnvironment = NULL
    mov qword ptr [rsp+56], 0   ; lpCurrentDirectory = NULL
    lea r8, [rsp+64]            ; lpStartupInfo
    lea r9, [rsp+168]           ; lpProcessInformation

    ; CreateProcessA(NULL, lpCommandLine, ...)
    xor rcx, rcx                ; lpApplicationName = NULL
    ; rdx already has lpCommandLine
    call CreateProcessA
    test eax, eax
    jz fail_start

    ; Wait for process completion up to timeout
    mov rcx, [rsp+168]          ; hProcess
    mov edx, edx                ; dwMilliseconds (from rdx lower 32-bits)
    call WaitForSingleObject

    ; Close handles
    mov rcx, [rsp+176]          ; hThread
    call CloseHandle
    mov rcx, [rsp+168]          ; hProcess
    call CloseHandle

    mov eax, 1
    jmp rc_exit

fail_start:
    ; Close any partially created handles if present
    mov rcx, [rsp+176]
    test rcx, rcx
    jz skip_close_thread
    call CloseHandle
skip_close_thread:
    mov rcx, [rsp+168]
    test rcx, rcx
    jz fail_return
    call CloseHandle
fail_return:
    xor eax, eax

rc_exit:
    add rsp, 176

    pop rsi pop rdi

    pop rbx

run_command ENDP

;==========================================================================
; agent_action_run_build() -> rax (bool)
;==========================================================================
agent_action_run_build PROC
    ; Use default build command
    lea rcx, szBuildDefaultCmd
    mov edx, 300000             ; 5 minutes default timeout
    call run_command
    ret
agent_action_run_build ENDP

;==========================================================================
; agent_action_run_test() -> rax (bool)
;==========================================================================
agent_action_run_test PROC
    ; Use default test command
    lea rcx, szTestDefaultCmd
    mov edx, 300000             ; 5 minutes default timeout
    call run_command
    ret
agent_action_run_test ENDP

;==========================================================================
; agent_action_executor_run(plan_ptr: rcx) -> rax (bool)
; Iterate tasks and dispatch to handlers
;==========================================================================
PUBLIC agent_action_executor_run
agent_action_executor_run PROC
    push rbx

    push rsi
    push rdi
    sub rsp, 48

    mov rbx, rcx                        ; plan*

    ; Log init
    lea rcx, szExecInit
    call console_log

    ; Load task_count and tasks_ptr
    mov esi, DWORD PTR [rbx + EXECUTION_PLAN_task_count]
    mov rdi, QWORD PTR [rbx + EXECUTION_PLAN_tasks_ptr]
    test esi, esi
    jnz have_tasks
    lea rcx, szNoTasks
    call console_log
    xor eax, eax
    jmp exec_exit

have_tasks:
    xor ecx, ecx                      ; i = 0
task_loop:
    cmp ecx, esi
    jge done_all

    ; Compute task slot pointer: tasks_ptr + i*SIZEOF TASK
    mov eax, ecx
    imul eax, 64                      ; Approximate SIZEOF TASK (aligned)
    mov r8, rdi
    add r8, rax

    ; Read task fields
    mov edx, DWORD PTR [r8 + TASK_task_type]
    mov r9, QWORD PTR [r8 + TASK_command]
    ; timeout currently not read from struct; use defaults in handlers

    ; Log task start
    mov eax, ecx
    lea rcx, szExecStart
    mov edx, eax
    mov r8d, DWORD PTR [r8 + TASK_task_type]
    call console_log
    
    ; If command provided, log it
    test r9, r9
    jz dispatch
    lea rcx, szExecCmd
    mov rdx, r9
    call console_log

dispatch:
    ; Record start time
    call GetTickCount64
    mov r11, rax

    ; Dispatch by task_type
    cmp edx, TASK_TYPE_BUILD
    je do_build
    cmp edx, TASK_TYPE_TEST
    je do_test
    cmp edx, TASK_TYPE_EXECUTE
    je do_execute
    ; Others: treat as validate/no-op for now
    jmp after_exec

do_build:
    call agent_action_run_build
    jmp after_exec

do_test:
    call agent_action_run_test
    jmp after_exec

do_execute:
    ; If command provided, run it; else no-op
    test r9, r9
    jz after_exec
    mov rcx, r9
    mov edx, 300000             ; default timeout 5 minutes
    call run_command
    jmp after_exec

after_exec:
    ; Measure duration
    mov r12d, eax                   ; status
    call GetTickCount64
    sub rax, r11
    mov r13d, eax                   ; elapsed ms (lower 32)

    ; Log completion
    lea rcx, szExecDone
    mov edx, ecx                    ; i
    mov r8d, r13d                   ; elapsed
    mov r9d, r12d                   ; status
    call console_log

    ; Next task
    inc ecx
    jmp task_loop

done_all:
    lea rcx, szExecDoneAll
    mov edx, esi
    call console_log
    mov eax, 1
    jmp exec_exit

exec_exit:
    add rsp, 48

    pop rsi pop rdi

    pop rbx

agent_action_executor_run ENDP

END





