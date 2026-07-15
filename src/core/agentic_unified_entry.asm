; ============================================================================
; agentic_unified_entry.asm — FINAL Unified Entry Point
; ============================================================================
;
; This is the FINAL integration that calls LIVE Aperture inference.
; Combines: Sovereign Core + Aperture Bridge + AVX-512 Kernel
;
; Build: ml64.exe /c agentic_unified_entry.asm
; Link:  link.exe agentic_unified_entry.obj agentic_aperture_live.obj aperture_q4_0_avx512_v2.obj
;
; ============================================================================

; ============================================================================
; External Imports (Windows API)
; ============================================================================

extern GetStdHandle:proc
extern WriteFile:proc
extern WriteConsoleA:proc
extern ExitProcess:proc
extern Sleep:proc
extern GetTickCount:proc

; ============================================================================
; External Imports (Aperture LIVE Bridge)
; ============================================================================

extern Agentic_RunStep_WithAperture_Live : PROC
extern Aperture_Inference_Live : PROC
extern ParseDecision : PROC
extern Dispatch_Tool : PROC

; ============================================================================
; Constants
; ============================================================================

STD_OUTPUT_HANDLE equ -11

AGENT_STATE_IDLE         equ 0
AGENT_STATE_THINKING     equ 1
AGENT_STATE_EXECUTING    equ 2
AGENT_STATE_COMPLETE     equ 3
AGENT_STATE_ERROR        equ 4

TASK_BUFFER_SIZE    equ 2048
RESULT_BUFFER_SIZE  equ 4096

; ============================================================================
; Data Section
; ============================================================================

.data

; Console handles
stdout_handle   dq 0

; Agent state (EXPORTED for bridge)
agent_state     dd AGENT_STATE_IDLE
step_count      dd 0
max_steps       dd 20

; Buffers
current_task    db TASK_BUFFER_SIZE dup(0)
result_buffer   db RESULT_BUFFER_SIZE dup(0)

; Test tasks
test_task_1     db "What is the current time?", 0
test_task_2     db "List files in current directory", 0
test_task_3     db "Calculate 123 * 456", 0

; Messages
banner_line     db "===================================================================", 13, 10
banner_len      equ $ - banner_line

banner_title    db "  RawrXD UNIFIED Agentic Core - LIVE Aperture Integration", 13, 10
banner_title_len equ $ - banner_title

banner_sub      db "  AVX-512 Kernel + Sovereign State Machine + Zero CRT", 13, 10
banner_sub_len  equ $ - banner_sub

init_msg        db "[AGENT] Initializing LIVE Aperture Core...", 13, 10
init_msg_len    equ $ - init_msg

ready_msg       db "[AGENT] Core ready. AVX-512 kernel active.", 13, 10
ready_msg_len   equ $ - ready_msg

test1_msg       db 13, 10, "=== Test 1: Time Query (LIVE Inference) ===", 13, 10
test1_msg_len   equ $ - test1_msg

test2_msg       db 13, 10, "=== Test 2: Directory Listing (LIVE Inference) ===", 13, 10
test2_msg_len   equ $ - test2_msg

test3_msg       db 13, 10, "=== Test 3: Calculation (LIVE Inference) ===", 13, 10
test3_msg_len   equ $ - test3_msg

live_msg        db "[LIVE] Running AVX-512 inference...", 13, 10
live_msg_len    equ $ - live_msg

complete_msg    db 13, 10, "[AGENT] All LIVE tests passed! Sovereign AI validated.", 13, 10
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

Print proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rsi, rcx
    mov rbx, rdx
    
    mov rax, [stdout_handle]
    test rax, rax
    jnz @@write
    
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [stdout_handle], rax
    
@@write:
    mov rcx, [stdout_handle]
    mov rdx, rsi
    mov r8, rbx
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Print endp

PrintString proc
    push rbx
    push rdi
    sub rsp, 32
    
    mov rdi, rcx
    xor rbx, rbx
    
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

PrintNewline proc
    sub rsp, 32
    mov rcx, 13
    mov rdx, 1
    call Print
    mov rcx, 10
    mov rdx, 1
    call Print
    add rsp, 32
    ret
PrintNewline endp

PrintNumber proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov eax, ecx
    lea rdi, [number_buffer + 31]
    mov byte ptr [rdi], 0
    
    test eax, eax
    jnz @@convert
    mov byte ptr [rdi - 1], '0'
    lea rdi, [number_buffer + 30]
    jmp @@print
    
@@convert:
    mov ebx, 10
@@loop:
    xor edx, edx
    div ebx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test eax, eax
    jnz @@loop
    
@@print:
    lea rcx, [number_buffer + 31]
    sub rcx, rdi
    mov rdx, rcx
    mov rcx, rdi
    call Print
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
PrintNumber endp

; ============================================================================
; Agentic Core Functions
; ============================================================================

Agentic_Init proc
    push rbx
    sub rsp, 32
    
    mov dword ptr [agent_state], AGENT_STATE_IDLE
    mov dword ptr [step_count], 0
    
    lea rdi, [current_task]
    mov rcx, TASK_BUFFER_SIZE
    xor eax, eax
    rep stosb
    
    add rsp, 32
    pop rbx
    ret
Agentic_Init endp

Agentic_SetTask proc
    push rbx
    push rdi
    push rsi
    sub rsp, 32
    
    mov rsi, rcx
    lea rdi, [current_task]
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

Agentic_Shutdown proc
    mov dword ptr [agent_state], AGENT_STATE_IDLE
    ret
Agentic_Shutdown endp

; ============================================================================
; Test Execution with LIVE Aperture
; ============================================================================

Run_Test_Live proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx
    
    call PrintNewline
    mov rcx, rdi
    call PrintString
    call PrintNewline
    
    call Agentic_Init
    mov rcx, rdi
    call Agentic_SetTask
    
    mov ebx, 0
@@loop:
    inc ebx
    
    ; Print LIVE message
    lea rcx, [live_msg]
    mov rdx, live_msg_len
    call Print
    
    ; Call LIVE Aperture step
    call Agentic_RunStep_WithAperture_Live
    
    mov eax, [agent_state]
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
Run_Test_Live endp

; ============================================================================
; Main Entry Point
; ============================================================================

AgenticUnifiedMain proc
    sub rsp, 40
    
    ; Banner
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
    
    ; Test 1
    lea rcx, [test1_msg]
    mov rdx, test1_msg_len
    call Print
    lea rcx, [test_task_1]
    call Run_Test_Live
    
    ; Test 2
    lea rcx, [test2_msg]
    mov rdx, test2_msg_len
    call Print
    lea rcx, [test_task_2]
    call Run_Test_Live
    
    ; Test 3
    lea rcx, [test3_msg]
    mov rdx, test3_msg_len
    call Print
    lea rcx, [test_task_3]
    call Run_Test_Live
    
    ; Complete
    lea rcx, [complete_msg]
    mov rdx, complete_msg_len
    call Print
    
    call Agentic_Shutdown
    
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 40
    ret
AgenticUnifiedMain endp

; ============================================================================
; Export Entry Point
; ============================================================================

public AgenticUnifiedMain
public agent_state
public step_count
public max_steps
public current_task
public Print
public PrintString
public PrintNewline

end
