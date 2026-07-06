; RawrXD_AgenticOrchestrator.asm — Agentic Orchestrator Kernel (MASM x64)
; 23-Handler VTable, SPSC Queue, Metrics
; Exports: asm_orchestrator_shutdown, asm_orchestrator_init, etc.

OPTION DOTNAME
OPTION CASEMAP:NONE

; ============================================================================
; Data Section
; ============================================================================
.DATA
ALIGN 16

; Orchestrator state
orch_initialized        QWORD 0
orch_handler_count      QWORD 23
orch_active_agents      QWORD 0
orch_shutdown_requested QWORD 0

; Handler vtable (23 entries)
handler_vtable          QWORD 23 DUP(0)

; SPSC Queue
SPSC_QUEUE_SIZE         EQU 1024
spsc_queue              QWORD SPSC_QUEUE_SIZE DUP(0)
spsc_head               QWORD 0
spsc_tail               QWORD 0

; Metrics
orch_metrics            QWORD 16 DUP(0)  ; [0]=tasks queued, [1]=tasks processed, etc.

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; asm_orchestrator_shutdown — Shutdown the orchestrator
; void asm_orchestrator_shutdown(void);
; ----------------------------------------------------------------------------
asm_orchestrator_shutdown PROC EXPORT
    push rbx
    push rsi
    push rdi
    push rcx
    
    ; Check if initialized
    mov rax, orch_initialized
    test rax, rax
    jz .shutdown_done
    
    ; Set shutdown flag
    mov orch_shutdown_requested, 1
    
    ; Signal all active agents to stop
    mov rcx, orch_active_agents
.agent_signal_loop:
    cmp rcx, 0
    je .agents_signaled
    ; Would signal each agent here
    dec rcx
    jmp .agent_signal_loop
.agents_signaled:
    
    ; Clear handler vtable
    lea rdi, handler_vtable
    xor rax, rax
    mov rcx, 23
    rep stosq
    
    ; Clear SPSC queue
    lea rdi, spsc_queue
    mov rcx, SPSC_QUEUE_SIZE
    rep stosq
    
    mov spsc_head, 0
    mov spsc_tail, 0
    
    ; Clear metrics
    lea rdi, orch_metrics
    mov rcx, 16
    rep stosq
    
    ; Reset state
    mov orch_initialized, 0
    mov orch_handler_count, 23
    mov orch_active_agents, 0
    mov orch_shutdown_requested, 0
    
.shutdown_done:
    pop rcx
    pop rdi
    pop rsi
    pop rbx
    ret
asm_orchestrator_shutdown ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_init — Initialize the orchestrator
; int asm_orchestrator_init(void);
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_orchestrator_init PROC EXPORT
    push rbx
    push rdi
    
    ; Check if already initialized
    mov rax, orch_initialized
    test rax, rax
    jnz .init_already
    
    ; Clear handler vtable
    lea rdi, handler_vtable
    xor rax, rax
    mov rcx, 23
    rep stosq
    
    ; Clear SPSC queue
    lea rdi, spsc_queue
    mov rcx, SPSC_QUEUE_SIZE
    rep stosq
    
    ; Clear metrics
    lea rdi, orch_metrics
    mov rcx, 16
    rep stosq
    
    ; Mark initialized
    mov orch_initialized, 1
    xor rax, rax
    jmp .init_done
    
.init_already:
    xor rax, rax          ; Already initialized = success
    
.init_done:
    pop rdi
    pop rbx
    ret
asm_orchestrator_init ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_register_handler — Register a handler
; int asm_orchestrator_register_handler(uint32_t index, uint64_t handlerAddr);
; RCX = handler index (0-22)
; RDX = handler address
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_orchestrator_register_handler PROC EXPORT
    ; Validate index
    cmp rcx, 23
    jae .reg_error
    
    ; Check initialized
    mov rax, orch_initialized
    test rax, rax
    jz .reg_error
    
    ; Store handler
    lea rax, handler_vtable
    mov [rax + rcx*8], rdx
    
    xor rax, rax
    ret
    
.reg_error:
    mov rax, -1
    ret
asm_orchestrator_register_handler ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_dispatch — Dispatch to handler
; int asm_orchestrator_dispatch(uint32_t handlerIndex, void* context);
; RCX = handler index
; RDX = context pointer
; Returns: handler result
; ----------------------------------------------------------------------------
asm_orchestrator_dispatch PROC EXPORT
    push rbx
    push rsi
    
    ; Validate index
    cmp rcx, 23
    jae .dispatch_error
    
    ; Check initialized
    mov rax, orch_initialized
    test rax, rax
    jz .dispatch_error
    
    ; Get handler
    lea rax, handler_vtable
    mov rbx, [rax + rcx*8]
    test rbx, rbx
    jz .dispatch_error
    
    ; Call handler
    mov rcx, rdx          ; context as first arg
    call rbx
    
    pop rsi
    pop rbx
    ret
    
.dispatch_error:
    mov rax, -1
    pop rsi
    pop rbx
    ret
asm_orchestrator_dispatch ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_enqueue — Enqueue task
; int asm_orchestrator_enqueue(uint32_t taskType, uint64_t taskData);
; RCX = task type
; RDX = task data
; Returns: 0 on success, -1 if queue full
; ----------------------------------------------------------------------------
asm_orchestrator_enqueue PROC EXPORT
    push rbx
    push rsi
    
    ; Check initialized
    mov rax, orch_initialized
    test rax, rax
    jz .enqueue_error
    
    ; Check shutdown
    mov rax, orch_shutdown_requested
    test rax, rax
    jnz .enqueue_error
    
    ; Calculate next head
    mov rbx, spsc_head
    inc rbx
    and rbx, SPSC_QUEUE_SIZE - 1
    
    ; Check if full (head would catch tail)
    cmp rbx, spsc_tail
    je .enqueue_error
    
    ; Store task
    mov rsi, spsc_head
    lea rax, spsc_queue
    mov [rax + rsi*8], rcx      ; task type
    mov [rax + rsi*8 + 8], rdx  ; task data
    
    ; Update head
    mov spsc_head, rbx
    
    ; Update metrics
    inc orch_metrics
    
    xor rax, rax
    pop rsi
    pop rbx
    ret
    
.enqueue_error:
    mov rax, -1
    pop rsi
    pop rbx
    ret
asm_orchestrator_enqueue ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_dequeue — Dequeue task
; int asm_orchestrator_dequeue(uint32_t* outTaskType, uint64_t* outTaskData);
; RCX = task type output
; RDX = task data output
; Returns: 0 on success, -1 if queue empty
; ----------------------------------------------------------------------------
asm_orchestrator_dequeue PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    mov rdi, rcx          ; task type out
    mov rsi, rdx          ; task data out
    
    ; Check initialized
    mov rax, orch_initialized
    test rax, rax
    jz .dequeue_error
    
    ; Check if empty
    mov rbx, spsc_head
    cmp rbx, spsc_tail
    je .dequeue_error
    
    ; Load task
    mov rbx, spsc_tail
    lea rax, spsc_queue
    mov rcx, [rax + rbx*8]
    mov r8, [rax + rbx*8 + 8]
    
    ; Store outputs
    mov [rdi], ecx
    mov [rsi], r8
    
    ; Update tail
    inc rbx
    and rbx, SPSC_QUEUE_SIZE - 1
    mov spsc_tail, rbx
    
    ; Update metrics
    inc orch_metrics+8
    
    xor rax, rax
    pop rdi
    pop rsi
    pop rbx
    ret
    
.dequeue_error:
    mov rax, -1
    pop rdi
    pop rsi
    pop rbx
    ret
asm_orchestrator_dequeue ENDP

; ----------------------------------------------------------------------------
; asm_orchestrator_get_metrics — Get metrics
; void asm_orchestrator_get_metrics(uint64_t* outMetrics, uint32_t maxEntries);
; RCX = output buffer
; RDX = max entries
; ----------------------------------------------------------------------------
asm_orchestrator_get_metrics PROC EXPORT
    push rsi
    push rdi
    push r12
    
    mov rdi, rcx
    mov rsi, rdx
    
    mov r12, 16
    cmp rsi, r12
    cmova rsi, r12
    
    lea rax, orch_metrics
    
.copy_metrics:
    cmp rsi, 0
    je .metrics_done
    mov rcx, [rax]
    mov [rdi], rcx
    add rax, 8
    add rdi, 8
    dec rsi
    jmp .copy_metrics
    
.metrics_done:
    pop rdi
    pop rsi
    ret
asm_orchestrator_get_metrics ENDP

END
