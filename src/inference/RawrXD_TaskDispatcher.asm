; ============================================================================
; RawrXD_TaskDispatcher.asm — Dependency-aware task dispatcher (SPSC)
; ============================================================================
; Task layout (64 entries max, 32 bytes each):
;   +0x00 qword func_ptr
;   +0x08 qword arg_ptr
;   +0x10 qword dep_mask
;   +0x18 qword state (0 idle, 1 queued, 2 ready, 3 running, 4 done)
;
; Exports:
;   RawrXD_TaskDispatcher_Init_Asm()
;   RawrXD_TaskDispatcher_Schedule_Asm(index, func_ptr, arg_ptr, dep_mask)
;   RawrXD_TaskDispatcher_Check_Asm(index) -> 1 ready, 0 blocked
;   RawrXD_TaskDispatcher_MarkDone_Asm(index)
;   RawrXD_TaskDispatcher_CompletionMask_Asm() -> current done bitmask
; ============================================================================

OPTION CASEMAP:NONE

MAX_TASKS    EQU 64
TASK_SIZE    EQU 32
STATE_IDLE   EQU 0
STATE_QUEUED EQU 1
STATE_READY  EQU 2
STATE_RUN    EQU 3
STATE_DONE   EQU 4

.data
ALIGN 16
g_task_queue      QWORD MAX_TASKS * (TASK_SIZE / 8) DUP(0)
g_completion_mask QWORD 0

.code

RawrXD_TaskDispatcher_Init_Asm PROC PUBLIC
    xor rax, rax
    mov rcx, MAX_TASKS * (TASK_SIZE / 8)
    lea rdx, g_task_queue
init_zero_loop:
    mov qword ptr [rdx], rax
    add rdx, 8
    loop init_zero_loop
    mov g_completion_mask, rax
    ret
RawrXD_TaskDispatcher_Init_Asm ENDP

RawrXD_TaskDispatcher_Schedule_Asm PROC PUBLIC
    ; RCX=index, RDX=func_ptr, R8=arg_ptr, R9=dep_mask
    cmp rcx, MAX_TASKS
    jae schedule_ret

    mov rax, rcx
    imul rax, TASK_SIZE
    lea r10, g_task_queue
    add r10, rax

    mov [r10 + 0], rdx
    mov [r10 + 8], r8
    mov [r10 + 16], r9
    mov qword ptr [r10 + 24], STATE_QUEUED

schedule_ret:
    ret
RawrXD_TaskDispatcher_Schedule_Asm ENDP

RawrXD_TaskDispatcher_Check_Asm PROC PUBLIC
    ; RCX=index, returns RAX=1 ready, 0 blocked
    xor rax, rax
    cmp rcx, MAX_TASKS
    jae check_ret

    mov r10, rcx
    imul r10, TASK_SIZE
    lea r11, g_task_queue
    add r11, r10

    mov r8, [r11 + 16]            ; dep_mask
    mov r9, g_completion_mask
    mov r10, r8
    and r10, r9                   ; satisfied deps
    cmp r10, r8
    jne check_ret

    mov qword ptr [r11 + 24], STATE_READY
    mov rax, 1

check_ret:
    ret
RawrXD_TaskDispatcher_Check_Asm ENDP

RawrXD_TaskDispatcher_MarkDone_Asm PROC PUBLIC
    ; RCX=index
    cmp rcx, MAX_TASKS
    jae mark_ret

    mov rax, 1
    shl rax, cl
    or g_completion_mask, rax

    mov r10, rcx
    imul r10, TASK_SIZE
    lea r11, g_task_queue
    add r11, r10
    mov qword ptr [r11 + 24], STATE_DONE

mark_ret:
    ret
RawrXD_TaskDispatcher_MarkDone_Asm ENDP

RawrXD_TaskDispatcher_CompletionMask_Asm PROC PUBLIC
    mov rax, g_completion_mask
    ret
RawrXD_TaskDispatcher_CompletionMask_Asm ENDP

END
