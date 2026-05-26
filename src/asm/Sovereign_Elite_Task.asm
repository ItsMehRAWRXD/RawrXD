; Sovereign_Overfeatured_Task.asm
include Sovereign_Common.inc
TASK_STATE STRUCT
    RSP_Save            dq 0
    RIP_Save            dq 0
    RBX_Save            dq 0
    RBP_Save            dq 0
    R12_Save            dq 0
    R13_Save            dq 0
    R14_Save            dq 0
    R15_Save            dq 0
    Status              dq 0
TASK_STATE ENDS
.DATA
    align 16
    g_TaskTable         TASK_STATE 16 DUP(<>)
    g_CurrentTaskID     dq -1
    g_KernelRSP         dq 0
.CODE
PUBLIC Sovereign_Yield
Sovereign_Yield PROC
    mov rax, [g_CurrentTaskID]
    cmp rax, -1
    je @@NoTask
    lea rdx, [g_TaskTable]
    imul rax, rax, TYPE TASK_STATE
    add rdx, rax
    mov [rdx + TASK_STATE.RSP_Save], rsp
    mov [rdx + TASK_STATE.RBX_Save], rbx
    mov [rdx + TASK_STATE.RBP_Save], rbp
    mov [rdx + TASK_STATE.R12_Save], r12
    mov [rdx + TASK_STATE.R13_Save], r13
    mov [rdx + TASK_STATE.R14_Save], r14
    mov [rdx + TASK_STATE.R15_Save], r15
    pop rax
    mov [rdx + TASK_STATE.RIP_Save], rax
    mov qword ptr [rdx + TASK_STATE.Status], 1
    mov rsp, [g_KernelRSP]
    ret
@@NoTask:
    ret
Sovereign_Yield ENDP
PUBLIC Sovereign_Schedule_Next
Sovereign_Schedule_Next PROC
    mov [g_KernelRSP], rsp
    xor rcx, rcx
@@Search:
    lea rdx, [g_TaskTable]
    mov rax, rcx
    imul rax, rax, TYPE TASK_STATE
    add rdx, rax
    cmp qword ptr [rdx + TASK_STATE.Status], 1
    je @@Found
    inc rcx
    cmp rcx, 16
    jl @@Search
    ret
@@Found:
    mov [g_CurrentTaskID], rcx
    mov qword ptr [rdx + TASK_STATE.Status], 2
    mov rbx, [rdx + TASK_STATE.RBX_Save]
    mov rbp, [rdx + TASK_STATE.RBP_Save]
    mov r12, [rdx + TASK_STATE.R12_Save]
    mov r13, [rdx + TASK_STATE.R13_Save]
    mov r14, [rdx + TASK_STATE.R14_Save]
    mov r15, [rdx + TASK_STATE.R15_Save]
    mov rsp, [rdx + TASK_STATE.RSP_Save]
    push [rdx + TASK_STATE.RIP_Save]
    ret
Sovereign_Schedule_Next ENDP
END
