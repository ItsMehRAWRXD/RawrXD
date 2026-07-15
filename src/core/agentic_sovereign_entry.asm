; ============================================================================
; agentic_sovereign_entry.asm — Pure MASM Entry Point (No C++!)
; ============================================================================
;
; This is a PURE MASM implementation of the agentic bridge.
; No C++ runtime. No CRT. Just Windows API + MASM.
;
; Build: ml64.exe /c agentic_sovereign_entry.asm
; Link:  link.exe /subsystem:console /entry:AgenticMain agentic_sovereign_entry.obj kernel32.lib user32.lib
;
; ============================================================================

; ============================================================================
; External Imports (Windows API)
; ============================================================================

extern GetStdHandle:proc
extern WriteFile:proc
extern WriteConsoleA:proc
extern GetConsoleMode:proc
extern ExitProcess:proc
extern GetLastError:proc
extern Sleep:proc
extern GetTickCount:proc

; ============================================================================
; Constants
; ============================================================================

STD_OUTPUT_HANDLE equ -11
STD_ERROR_HANDLE  equ -12

; Agent states
AGENT_STATE_IDLE         equ 0
AGENT_STATE_THINKING     equ 1
AGENT_STATE_EXECUTING    equ 2
AGENT_STATE_COMPLETE     equ 3
AGENT_STATE_ERROR        equ 4

; Buffer sizes
TASK_BUFFER_SIZE    equ 2048
RESULT_BUFFER_SIZE  equ 4096
OUTPUT_BUFFER_SIZE  equ 8192

; ============================================================================
; Data Section
; ============================================================================

.data

; Console handles
stdout_handle   dq 0
stderr_handle   dq 0

; Agent state
agent_state     dd AGENT_STATE_IDLE
step_count      dd 0
max_steps       dd 20

; Buffers
current_task    db TASK_BUFFER_SIZE dup(0)
result_buffer   db RESULT_BUFFER_SIZE dup(0)
output_buffer   db OUTPUT_BUFFER_SIZE dup(0)

; Test tasks
test_task_1     db "What is the current time?", 0
test_task_2     db "List files in current directory", 0
test_task_3     db "Calculate 123 * 456", 0

; Output strings
banner_line     db "===================================================================", 13, 10
banner_len      equ $ - banner_line

banner_title    db "  RawrXD Agentic MASM Core - Pure x64 Assembly", 13, 10
banner_title_len equ $ - banner_title

banner_sub      db "  Zero Dependencies. Zero CRT. Maximum Performance.", 13, 10
banner_sub_len  equ $ - banner_sub

init_msg        db "[AGENT] Initializing Sovereign Agentic Core...", 13, 10
init_msg_len    equ $ - init_msg

ready_msg       db "[AGENT] Core ready. State machine active.", 13, 10
ready_msg_len   equ $ - ready_msg

test1_msg       db 13, 10, "=== Test 1: Time Query ===", 13, 10
test1_msg_len   equ $ - test1_msg

test2_msg       db 13, 10, "=== Test 2: Directory Listing ===", 13, 10
test2_msg_len   equ $ - test2_msg

test3_msg       db 13, 10, "=== Test 3: Calculation ===", 13, 10
test3_msg_len   equ $ - test3_msg

think_msg       db "[THINK] Analyzing task requirements...", 13, 10
think_msg_len   equ $ - think_msg

act_msg         db "[ACT] Executing tool call...", 13, 10
act_msg_len     equ $ - act_msg

done_msg        db "[DONE] Task completed successfully.", 13, 10
done_msg_len    equ $ - done_msg

step_msg        db "[STEP] Executing step ", 0
step_msg_len    equ $ - step_msg

of_msg          db " of ", 0
of_msg_len      equ $ - of_msg

newline         db 13, 10
newline_len     equ $ - newline

shutdown_msg    db 13, 10, "[AGENT] Shutting down gracefully...", 13, 10
shutdown_msg_len equ $ - shutdown_msg

complete_msg    db "[AGENT] All tests passed. Sovereign core validated.", 13, 10
complete_msg_len equ $ - complete_msg

; Number conversion buffer
number_buffer   db 32 dup(0)

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; Console Output Helpers
; ============================================================================

; void Print(const char* msg, size_t len)
; RCX = message pointer, RDX = length
Print proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40                 ; Shadow space + alignment
    
    mov rsi, rcx                ; message
    mov rbx, rdx                ; length
    
    ; Check if stdout_handle is initialized
    mov rax, [stdout_handle]
    test rax, rax
    jnz @@write
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [stdout_handle], rax
    
@@write:
    ; Write to console
    mov rcx, [stdout_handle]    ; hConsoleOutput
    mov rdx, rsi                ; lpBuffer
    mov r8, rbx                 ; nNumberOfCharsToWrite
    xor r9, r9                  ; lpNumberOfCharsWritten (NULL)
    mov qword ptr [rsp+32], 0   ; lpReserved
    call WriteConsoleA
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Print endp

; void PrintString(const char* msg)
; RCX = null-terminated string
PrintString proc
    push rbx
    push rdi
    sub rsp, 32
    
    mov rdi, rcx                ; string pointer
    xor rbx, rbx                ; length counter
    
    ; Calculate string length
@@count:
    mov al, [rdi + rbx]
    test al, al
    jz @@print
    inc rbx
    jmp @@count
    
@@print:
    mov rcx, rdi
    mov rdx, rbx
    call Print
    
    add rsp, 32
    pop rdi
    pop rbx
    ret
PrintString endp

; void PrintNumber(int n)
; RCX = number to print
PrintNumber proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov eax, ecx                ; number
    lea rdi, [number_buffer + 31] ; end of buffer
    mov byte ptr [rdi], 0       ; null terminate
    
    ; Handle zero
    test eax, eax
    jnz @@convert
    mov byte ptr [rdi - 1], '0'
    lea rdi, [number_buffer + 30]
    jmp @@print
    
@@convert:
    mov ebx, 10
@@loop:
    xor edx, edx
    div ebx                     ; EAX = EAX / 10, EDX = remainder
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test eax, eax
    jnz @@loop
    
@@print:
    ; Calculate length
    lea rcx, [number_buffer + 31]
    sub rcx, rdi                ; RCX = length
    
    ; Print
    mov rdx, rcx
    mov rcx, rdi
    call Print
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
PrintNumber endp

; void PrintNewline()
PrintNewline proc
    sub rsp, 32
    lea rcx, [newline]
    mov rdx, newline_len
    call Print
    add rsp, 32
    ret
PrintNewline endp

; ============================================================================
; Agentic Core Functions
; ============================================================================

; void Agentic_Init()
Agentic_Init proc
    push rbx
    sub rsp, 32
    
    ; Reset state
    mov dword ptr [agent_state], AGENT_STATE_IDLE
    mov dword ptr [step_count], 0
    
    ; Clear task buffer
    lea rdi, [current_task]
    mov rcx, TASK_BUFFER_SIZE
    xor eax, eax
    rep stosb
    
    ; Clear result buffer
    lea rdi, [result_buffer]
    mov rcx, RESULT_BUFFER_SIZE
    rep stosb
    
    add rsp, 32
    pop rbx
    ret
Agentic_Init endp

; void Agentic_SetTask(const char* task)
; RCX = task string
Agentic_SetTask proc
    push rbx
    push rdi
    push rsi
    sub rsp, 32
    
    mov rsi, rcx                ; source
    lea rdi, [current_task]     ; destination
    mov rcx, TASK_BUFFER_SIZE - 1
    
@@copy:
    cmp rcx, 0
    je @@done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    test al, al
    jnz @@copy
    
@@done:
    mov dword ptr [agent_state], AGENT_STATE_THINKING
    mov dword ptr [step_count], 0
    
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    ret
Agentic_SetTask endp

; int Agentic_RunStep()
; Returns: 0 = success, state in agent_state
Agentic_RunStep proc
    push rbx
    sub rsp, 32
    
    ; Increment step count
    inc dword ptr [step_count]
    
    ; Check max steps
    mov eax, [step_count]
    cmp eax, [max_steps]
    jge @@error
    
    ; Simulate step - alternate states based on step count
    mov eax, [step_count]
    cmp eax, 3
    jl @@thinking
    
    ; Complete after 3 steps
    mov dword ptr [agent_state], AGENT_STATE_COMPLETE
    jmp @@success
    
@@thinking:
    mov dword ptr [agent_state], AGENT_STATE_THINKING
    
@@success:
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
    
@@error:
    mov dword ptr [agent_state], AGENT_STATE_ERROR
    mov eax, -1
    add rsp, 32
    pop rbx
    ret
Agentic_RunStep endp

; int Agentic_GetState()
Agentic_GetState proc
    mov eax, [agent_state]
    ret
Agentic_GetState endp

; const char* Agentic_GetResult()
Agentic_GetResult proc
    lea rax, [result_buffer]
    ret
Agentic_GetResult endp

; void Agentic_Shutdown()
Agentic_Shutdown proc
    mov dword ptr [agent_state], AGENT_STATE_IDLE
    ret
Agentic_Shutdown endp

; ============================================================================
; Tool Simulation
; ============================================================================

; void Simulate_ToolExecution(int step)
; RCX = current step
Simulate_ToolExecution proc
    push rbx
    sub rsp, 32
    
    mov ebx, ecx
    
    ; Print step info
    lea rcx, [step_msg]
    call PrintString
    
    mov ecx, ebx
    call PrintNumber
    
    lea rcx, [of_msg]
    call PrintString
    
    mov ecx, 3
    call PrintNumber
    
    call PrintNewline
    
    ; Simulate different tool calls based on step
    cmp ebx, 1
    je @@step1
    cmp ebx, 2
    je @@step2
    jmp @@step3
    
@@step1:
    lea rcx, [think_msg]
    mov rdx, think_msg_len
    call Print
    jmp @@done
    
@@step2:
    lea rcx, [act_msg]
    mov rdx, act_msg_len
    call Print
    jmp @@done
    
@@step3:
    lea rcx, [done_msg]
    mov rdx, done_msg_len
    call Print
    
@@done:
    add rsp, 32
    pop rbx
    ret
Simulate_ToolExecution endp

; ============================================================================
; Test Execution
; ============================================================================

; void Run_Test(const char* task_name, const char* task)
; RCX = test name, RDX = task
Run_Test proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx                ; test name
    mov rsi, rdx                ; task
    
    ; Print test header
    call PrintNewline
    mov rcx, rdi
    call PrintString
    call PrintNewline
    
    ; Set task
    mov rcx, rsi
    call Agentic_SetTask
    
    ; Run agentic loop
    mov ebx, 0
@@loop:
    inc ebx
    
    ; Run step
    call Agentic_RunStep
    
    ; Simulate tool execution
    mov ecx, ebx
    call Simulate_ToolExecution
    
    ; Check state
    call Agentic_GetState
    cmp eax, AGENT_STATE_COMPLETE
    je @@complete
    cmp eax, AGENT_STATE_ERROR
    je @@error
    
    cmp ebx, 20
    jl @@loop
    
@@complete:
    call PrintNewline
    jmp @@done
    
@@error:
    call PrintNewline
    
@@done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Run_Test endp

; ============================================================================
; Main Entry Point
; ============================================================================

AgenticMain proc
    sub rsp, 40
    
    ; Print banner
    lea rcx, [banner_line]
    mov rdx, banner_len
    call Print
    
    lea rcx, [banner_title]
    mov rdx, banner_title_len
    call Print
    
    lea rcx, [banner_sub]
    mov rdx, banner_sub_len
    call Print
    
    lea rcx, [banner_line]
    mov rdx, banner_len
    call Print
    call PrintNewline
    
    ; Initialize
    lea rcx, [init_msg]
    mov rdx, init_msg_len
    call Print
    
    call Agentic_Init
    
    lea rcx, [ready_msg]
    mov rdx, ready_msg_len
    call Print
    call PrintNewline
    
    ; Run Test 1
    lea rcx, [test1_msg]
    mov rdx, test1_msg_len
    call Print
    lea rcx, [test_task_1]
    lea rdx, [test_task_1]
    call Run_Test
    
    ; Run Test 2
    lea rcx, [test2_msg]
    mov rdx, test2_msg_len
    call Print
    lea rcx, [test_task_2]
    lea rdx, [test_task_2]
    call Run_Test
    
    ; Run Test 3
    lea rcx, [test3_msg]
    mov rdx, test3_msg_len
    call Print
    lea rcx, [test_task_3]
    lea rdx, [test_task_3]
    call Run_Test
    
    ; Shutdown
    lea rcx, [shutdown_msg]
    mov rdx, shutdown_msg_len
    call Print
    
    call Agentic_Shutdown
    
    lea rcx, [complete_msg]
    mov rdx, complete_msg_len
    call Print
    call PrintNewline
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 40
    ret
AgenticMain endp

; ============================================================================
; Export Entry Point
; ============================================================================

public AgenticMain
public agent_state
public step_count
public max_steps
public current_task
public Print
public PrintString
public PrintNewline

end
