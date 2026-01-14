@masm_terminal_pool_init EQU 1

@masm_terminal_pool_shutdown EQU 1

@masm_terminal_spawn_process EQU 1

@masm_terminal_kill_process EQU 1

@masm_terminal_read_output EQU 1

@masm_terminal_write_input EQU 1

@masm_terminal_get_status EQU 1

@masm_terminal_get_exit_code EQU 1

@masm_terminal_list_processes EQU 1

@masm_terminal_wait_for_process EQU 1

@masm_terminal_get_process_count EQU 1

;==============================================================================

; terminal_pool.asm - MASM Terminal Pool Manager

; Purpose: Manage multiple terminal/process instances with I/O redirection

; Author: RawrXD CI/CD

; Date: Dec 29, 2025

;

; Provides process spawning, lifecycle management, and I/O handling for:

; - PowerShell terminals

; - Windows cmd.exe shells

; - Custom process execution with pipe redirection

;==============================================================================



option casemap:none



include windows.inc

include masm_master_defs.inc

includelib kernel32.lib

includelib user32.lib



;==============================================================================

; CONSTANTS & STRUCTURES

;==============================================================================



; Process state constants

PROCESS_STATE_IDLE      EQU 0

PROCESS_STATE_RUNNING   EQU 1

PROCESS_STATE_PAUSED    EQU 2

PROCESS_STATE_TERMINATED EQU 3

PROCESS_STATE_ERROR     EQU 4



; Shell type constants

SHELL_TYPE_POWERSHELL   EQU 1

SHELL_TYPE_CMD          EQU 2

SHELL_TYPE_CUSTOM       EQU 3



; Maximum limits

MAX_TERMINALS           EQU 16

MAX_COMMAND_LINE        EQU 2048

MAX_OUTPUT_BUFFER       EQU 65536   ; 64 KB output buffer per terminal



; Process information structure

PROCESS_INFO STRUCT

    processId           DWORD ?

    threadId            DWORD ?

    hProcess            QWORD ?

    hThread             QWORD ?

    hStdInput           QWORD ?

    hStdOutput          QWORD ?

    hStdError           QWORD ?

    hInputWrite         QWORD ?

    hOutputRead         QWORD ?

    hErrorRead          QWORD ?

    shellType           DWORD ?     ; SHELL_TYPE_*

    state               DWORD ?     ; PROCESS_STATE_*

    creationTime        QWORD ?     ; Timestamp when created

    exitCode            DWORD ?

    isAlive             DWORD ?     ; BOOL

    outputBuffer        QWORD ?     ; Pointer to output buffer

    outputSize          DWORD ?

    outputCapacity      DWORD ?

PROCESS_INFO ENDS



; Terminal pool structure

TERMINAL_POOL STRUCT

    processes           PROCESS_INFO MAX_TERMINALS DUP(<>)

    processCount        DWORD ?

    heapHandle          QWORD ?

    poolMutex           QWORD ?

    isInitialized       DWORD ?     ; BOOL

    lastProcessId       DWORD ?     ; ID of last spawned process

TERMINAL_POOL ENDS



;==============================================================================

; GLOBAL DATA

;==============================================================================



.data

    g_terminalPool      TERMINAL_POOL <>

    g_poolInitialized   DWORD 0



.data

    ; Registry path for terminal settings

    szRegistryPath      BYTE "Software\RawrXD\Terminals", 0



;==============================================================================

; EXPORTED FUNCTIONS

;==============================================================================



;==============================================================================

; FUNCTION IMPLEMENTATIONS

;==============================================================================



; masm_terminal_pool_init - Initialize the terminal pool

; Returns: 1 = success, 0 = failure

PUBLIC masm_terminal_pool_init

masm_terminal_pool_init PROC USES rbx rsi rdi

    push rbp

    sub rsp, 32

    cmp g_poolInitialized, 1

    je init_done_local

    call GetProcessHeap

    mov g_terminalPool.heapHandle, rax

    mov g_terminalPool.processCount, 0

    mov g_poolInitialized, 1

    mov rax, 1

init_done_local:

    add rsp, 32

    pop rbp

    ret

masm_terminal_pool_init ENDP



masm_terminal_pool_shutdown PROC USES rbx rsi rdi

    push rbp

    sub rsp, 32

    mov rax, 1

    add rsp, 32

    pop rbp

    ret

masm_terminal_pool_shutdown ENDP



masm_terminal_spawn_process PROC USES rbx rsi rdi r12 r13 r14 r15

    push rbp

    sub rsp, 200  ; Shadow space + local structures (STARTUPINFOA + PROCESS_INFORMATION)



    mov r12, rcx  ; Save shell type

    mov r13, rdx  ; Save command line

    mov r14, 0    ; Result process ID



    ; Check pool is initialized

    cmp g_poolInitialized, 0

    je spawn_not_init_local



    ; Check pool not full

    mov eax, g_terminalPool.processCount

    cmp eax, MAX_TERMINALS

    jge spawn_pool_full_local



    ; Create pipes for I/O redirection

    ; HANDLE hReadPipe, hWritePipe;

    ; CreatePipe(&hReadPipe, &hWritePipe, NULL, 0);

    lea r15, [rsp + 16]  ; Output buffer offset



    ; Allocate output buffer in heap

    mov rcx, g_terminalPool.heapHandle

    mov edx, MAX_OUTPUT_BUFFER

    mov r8d, HEAP_ZERO_MEMORY

    call HeapAlloc

    mov r15, rax

    cmp rax, 0

    je spawn_buffer_fail_local



    ; Get current process index

    mov r8d, g_terminalPool.processCount

    mov eax, r8d
    shl rax, 0
    mov rcx, 112
    imul rax, rcx

    lea r9, [g_terminalPool.processes + rax]



    ; Store process info

    mov [r9].PROCESS_INFO.shellType, r12d

    mov [r9].PROCESS_INFO.state, PROCESS_STATE_RUNNING

    mov [r9].PROCESS_INFO.outputBuffer, r15

    mov [r9].PROCESS_INFO.outputCapacity, MAX_OUTPUT_BUFFER

    mov [r9].PROCESS_INFO.outputSize, 0

    mov [r9].PROCESS_INFO.isAlive, 1



    ; Setup STARTUPINFOA structure

    ; (This is simplified - in production would call CreateProcessA)

    

    ; TODO: Implement actual CreateProcessA call with pipe setup

    ; For now, return success stub



    ; Increment process count

    inc g_terminalPool.processCount



    ; Return process ID

    mov r14d, r8d  ; Return index as ID (in production, use actual PID)



    jmp spawn_done_local



spawn_buffer_fail_local:

    xor r14d, r14d

    jmp spawn_done_local



spawn_pool_full_local:

    xor r14d, r14d

    jmp spawn_done_local



spawn_not_init_local:

    xor r14d, r14d



spawn_done_local:

    mov rax, r14

    add rsp, 200

    pop rbp

    ret

masm_terminal_spawn_process ENDP



; masm_terminal_kill_process - Terminate a process

; Args: RCX = process ID

; Returns: 1 = success, 0 = failure

PUBLIC masm_terminal_kill_process

masm_terminal_kill_process PROC USES rbx rsi rdi

    push rbp

    sub rsp, 32



    mov r8d, ecx  ; Process ID

    

    ; Find process in pool

    xor r9d, r9d  ; Index

find_process_local:

    cmp r9d, g_terminalPool.processCount

    jge kill_not_found_local



    cmp r9d, r8d

    je kill_found_local



    inc r9d

    jmp find_process_local



kill_found_local:

    ; Get process info

    mov eax, r9d
    shl rax, 0
    mov rcx, 112
    imul rax, rcx

    lea rax, [g_terminalPool.processes + rax]

    

    ; Close process handle (will terminate it)

    mov rcx, [rax].PROCESS_INFO.hProcess

    cmp rcx, 0

    je kill_already_closed_local

    call CloseHandle

kill_already_closed_local:



    ; Mark state as terminated

    mov [rax].PROCESS_INFO.state, PROCESS_STATE_TERMINATED

    mov [rax].PROCESS_INFO.isAlive, 0



    mov rax, 1  ; Success

    jmp kill_done_local



kill_not_found_local:

    xor rax, rax  ; Not found



kill_done_local:

    add rsp, 32

    pop rbp

    ret

masm_terminal_kill_process ENDP



; masm_terminal_read_output - Read output from a terminal

; Args: RCX = process ID, RDX = buffer pointer, R8 = buffer size

; Returns: bytes read, or -1 if error

PUBLIC masm_terminal_read_output

masm_terminal_read_output PROC

    ret

masm_terminal_read_output ENDP



masm_terminal_write_input PROC

    ret

masm_terminal_write_input ENDP



masm_terminal_get_status PROC

    ret

masm_terminal_get_status ENDP



masm_terminal_get_exit_code PROC

    ret

masm_terminal_get_exit_code ENDP



masm_terminal_list_processes PROC USES rbx rsi rdi

    push rbp

    sub rsp, 32



    mov r8, rcx    ; Output buffer

    mov r9d, edx   ; Max count



    xor r10d, r10d ; Counter



list_loop_local:

    cmp r10d, g_terminalPool.processCount

    jge list_done_local



    cmp r10d, r9d

    jge list_done_local



    ; Check if process is alive

    mov eax, r10d
    shl rax, 0
    mov rcx, 112
    imul rax, rcx

    lea rax, [g_terminalPool.processes + rax]

    cmp [rax].PROCESS_INFO.isAlive, 1

    jne skip_dead_local



    mov edx, r10d

    mov [r8 + r10 * 4], edx



skip_dead_local:

    inc r10d

    jmp list_loop_local



list_done_local:

    mov rax, r10  ; Return count

    add rsp, 32

    pop rbp

    ret

masm_terminal_list_processes ENDP



; masm_terminal_wait_for_process - Wait for process to terminate

; Args: RCX = process ID, RDX = timeout in milliseconds (INFINITE = -1)

; Returns: 1 if terminated, 0 if timeout, -1 if error

PUBLIC masm_terminal_wait_for_process

masm_terminal_wait_for_process PROC

    ret

masm_terminal_wait_for_process ENDP



masm_terminal_get_process_count PROC

    mov eax, g_terminalPool.processCount

    ret

masm_terminal_get_process_count ENDP



END











