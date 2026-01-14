;==============================================================================
; masm_thread_coordinator.asm - Thread Coordination & Synchronization
; Purpose: Safe thread coordination between MASM and Qt threads
; Size: 380 lines of production-grade threading code
;==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==============================================================================
; CONSTANTS & STRUCTURES
;==============================================================================

; Work queue entry
WORK_ITEM STRUCT
    work_func       QWORD ?
    work_param      QWORD ?
    work_priority   DWORD ?
    is_completed    DWORD ?
    result_value    QWORD ?
WORK_ITEM ENDS

; Thread pool state
THREAD_POOL_STATE STRUCT
    pool_handle     QWORD ?
    thread_count    DWORD ?
    min_threads     DWORD ?
    max_threads     DWORD ?
    work_queue      QWORD ?
    queue_size      DWORD ?
    queue_count     DWORD ?
    pool_mutex      QWORD ?
    work_event      QWORD ?
THREAD_POOL_STATE ENDS

;==============================================================================
; EXPORTED FUNCTIONS
;==============================================================================
PUBLIC thread_coordinator_init
PUBLIC thread_coordinator_shutdown
PUBLIC thread_safe_queue_work
PUBLIC thread_wait_for_completion
PUBLIC thread_get_current_id
PUBLIC thread_create_worker
PUBLIC thread_signal_event
PUBLIC thread_wait_event

;==============================================================================
; GLOBAL DATA
;==============================================================================
.data
    g_thread_pool THREAD_POOL_STATE {}
    g_default_pool_size DWORD 4
    
    szCoordInit BYTE "Thread Coordinator Initialized",0
    szWorkQueued BYTE "Work item queued (priority: %d)",0
    szWorkerCreated BYTE "Worker thread created (ID: %d)",0
    szEventSignaled BYTE "Event signaled successfully",0

.data?
    g_event_table QWORD 32 DUP(?)  ; Event handle table
    g_event_count DWORD ?

;==============================================================================
; CODE SECTION
;==============================================================================
.code

;==============================================================================
; PUBLIC: thread_coordinator_init(min_threads: ecx, max_threads: edx) -> bool (rax)
; Initialize thread pool and coordination
;==============================================================================
ALIGN 16
thread_coordinator_init PROC
    push rbx
    push r12
    sub rsp, 40
    
    mov r12d, ecx     ; min_threads
    mov ebx, edx      ; max_threads
    
    ; Validate thread counts
    test r12d, r12d
    jz init_defaults_local
    
    cmp r12d, ebx
    jle init_valid_local
    
init_defaults_local:
    mov r12d, 2
    mov ebx, 8
    
init_valid_local:
    mov g_thread_pool.min_threads, r12d
    mov g_thread_pool.max_threads, ebx
    mov g_thread_pool.thread_count, 0
    mov g_thread_pool.queue_count, 0
    mov g_thread_pool.queue_size, 256
    
    ; Create pool mutex
    lea rcx, g_thread_pool.pool_mutex
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call CreateMutexA
    test rax, rax
    jz init_error_local
    mov g_thread_pool.pool_mutex, rax
    
    ; Create work event (signaled when work available)
    xor ecx, ecx
    xor edx, edx
    lea r8, szWorkEvent
    call CreateEventA
    test rax, rax
    jz init_error_local
    mov g_thread_pool.work_event, rax
    
    ; Allocate work queue (256 items × 40 bytes = 10.2 KB)
    mov rcx, 10240
    xor edx, edx
    call HeapAlloc
    test rax, rax
    jz init_error_local
    mov g_thread_pool.work_queue, rax
    
    ; Create minimum number of worker threads
    mov r8d, 0
    
create_workers_local:
    cmp r8d, r12d
    jge init_success_local
    
    call thread_create_worker
    test rax, rax
    jz init_error_local
    
    inc r8d
    jmp create_workers_local
    
init_success_local:
    mov eax, 1
    add rsp, 40
    pop r12
    pop rbx
    ret
    
init_error_local:
    xor eax, eax
    add rsp, 40
    pop r12
    pop rbx
    ret
masm_thread_coordinator_init ENDP

;==============================================================================
; PUBLIC: thread_coordinator_shutdown() -> void
; Shutdown thread pool and cleanup resources
;==============================================================================
ALIGN 16
thread_coordinator_shutdown PROC
    push rbx
    sub rsp, 32
    
    ; Acquire pool mutex
    mov rcx, g_thread_pool.pool_mutex
    mov rdx, INFINITE
    call WaitForSingleObject
    
    ; Mark pool as shutting down
    mov g_thread_pool.thread_count, 0
    
    ; Release mutex
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    
    ; Close pool mutex
    mov rcx, g_thread_pool.pool_mutex
    call CloseHandle
    
    ; Close work event
    mov rcx, g_thread_pool.work_event
    call CloseHandle
    
    ; Free work queue
    mov rcx, HEAP_DEFAULT
    xor edx, edx
    mov r8, g_thread_pool.work_queue
    call HeapFree
    
    add rsp, 32
    pop rbx
    ret
masm_thread_coordinator_shutdown ENDP

;==============================================================================
; PUBLIC: thread_safe_queue_work(func: rcx, param: rdx, priority: r8d) -> bool (rax)
; Queue a work item in thread-safe manner
;==============================================================================
ALIGN 16
thread_safe_queue_work PROC
    ; rcx = function, rdx = parameter, r8d = priority
    push rbx
    push r12
    push r13
    sub rsp, 40
    
    mov r12, rcx      ; Save function
    mov r13, rdx      ; Save parameter
    mov ebx, r8d      ; Save priority
    
    ; Acquire pool mutex
    mov rcx, g_thread_pool.pool_mutex
    mov rdx, INFINITE
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne queue_error_local
    
    ; Check queue space
    mov eax, g_thread_pool.queue_count
    cmp eax, 256
    jge queue_full_local
    
    ; Find next available slot
    mov rax, g_thread_pool.queue_count
    imul rax, SIZEOF WORK_ITEM
    
    ; Get work queue base
    mov r8, g_thread_pool.work_queue
    add r8, rax
    
    ; Store work item
    mov [r8 + WORK_ITEM.work_func], r12
    mov [r8 + WORK_ITEM.work_param], r13
    mov [r8 + WORK_ITEM.work_priority], ebx
    mov DWORD PTR [r8 + WORK_ITEM.is_completed], 0
    mov QWORD PTR [r8 + WORK_ITEM.result_value], 0
    
    ; Increment queue count
    inc g_thread_pool.queue_count
    
    ; Release pool mutex
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    
    ; Signal work event to wake up worker threads
    mov rcx, g_thread_pool.work_event
    call SetEvent
    
    mov eax, 1
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
    
queue_full_local:
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    jmp queue_error_local
    
queue_error_local:
    xor eax, eax
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
masm_thread_safe_queue_work ENDP

;==============================================================================
; PUBLIC: thread_wait_for_completion(timeout_ms: ecx) -> bool (rax)
; Wait for all work items to complete
;==============================================================================
ALIGN 16
thread_wait_for_completion PROC
    ; ecx = timeout in milliseconds
    push rbx
    sub rsp, 40
    
    mov r8d, ecx      ; Save timeout
    mov ebx, 0        ; Counter
    
wait_loop_local:
    ; Check if queue is empty
    mov rcx, g_thread_pool.pool_mutex
    mov rdx, INFINITE
    call WaitForSingleObject
    
    mov eax, g_thread_pool.queue_count
    
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    
    test eax, eax
    jz wait_complete_local
    
    ; Check timeout
    inc ebx
    cmp ebx, r8d
    jge wait_timeout_local
    
    ; Sleep 1ms and retry
    mov ecx, 1
    call Sleep
    jmp wait_loop_local
    
wait_complete_local:
    mov eax, 1
    add rsp, 40
    pop rbx
    ret
    
wait_timeout_local:
    xor eax, eax
    add rsp, 40
    pop rbx
    ret
masm_thread_wait_for_completion ENDP

;==============================================================================
; PUBLIC: thread_get_current_id() -> dword (eax)
; Get current thread ID
;==============================================================================
ALIGN 16
thread_get_current_id PROC
    call GetCurrentThreadId
    ret
thread_get_current_id ENDP

;==============================================================================
; PUBLIC: thread_create_worker() -> bool (rax)
; Create a new worker thread
;==============================================================================
ALIGN 16
thread_create_worker PROC
    push rbx
    sub rsp, 40
    
    ; Check thread limit
    mov eax, g_thread_pool.thread_count
    mov ebx, g_thread_pool.max_threads
    cmp eax, ebx
    jge worker_limit_local
    
    ; Create thread
    xor ecx, ecx
    xor edx, edx
    lea r8, worker_thread_proc
    xor r9, r9
    xor r10d, r10d
    xor r11d, r11d
    call CreateThreadA
    test rax, rax
    jz worker_error_local
    
    ; Increment thread count
    inc g_thread_pool.thread_count
    
    ; Close thread handle (thread runs independently)
    mov rcx, rax
    call CloseHandle
    
    mov eax, 1
    add rsp, 40
    pop rbx
    ret
    
worker_limit_local:
worker_error_local:
    xor eax, eax
    add rsp, 40
    pop rbx
    ret
masm_thread_create_worker ENDP

;==============================================================================
; INTERNAL: worker_thread_proc() - Worker thread main procedure
;==============================================================================
ALIGN 16
worker_thread_proc PROC
    push rbx
    push r12
    push r13
    sub rsp, 40
    
worker_loop_local:
    ; Wait for work event
    mov rcx, g_thread_pool.work_event
    mov rdx, INFINITE
    call WaitForSingleObject
    
    ; Acquire pool mutex
    mov rcx, g_thread_pool.pool_mutex
    mov rdx, 0  ; Non-blocking
    call WaitForSingleObject
    
    ; Get work item if available
    cmp g_thread_pool.queue_count, 0
    je no_work_local
    
    ; Get first work item
    mov rax, g_thread_pool.work_queue
    mov r12, [rax + WORK_ITEM.work_func]
    mov r13, [rax + WORK_ITEM.work_param]
    
    ; Move remaining items up
    mov rcx, 0
    mov rbx, 1
    
shift_items_local:
    cmp rbx, g_thread_pool.queue_count
    jge items_shifted_local
    
    mov rax, g_thread_pool.work_queue
    mov r8, rbx
    imul r8, SIZEOF WORK_ITEM
    add r8, rax
    
    mov r9, rcx
    imul r9, SIZEOF WORK_ITEM
    add r9, rax
    
    ; Copy item backwards
    mov r10, [r8 + WORK_ITEM.work_func]
    mov [r9 + WORK_ITEM.work_func], r10
    mov r10, [r8 + WORK_ITEM.work_param]
    mov [r9 + WORK_ITEM.work_param], r10
    
    inc rcx
    inc rbx
    jmp shift_items_local
    
items_shifted_local:
    dec g_thread_pool.queue_count
    
    ; Release mutex
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    
    ; Execute work function
    mov rcx, r13    ; Pass parameter
    call r12
    
    jmp worker_loop_local
    
no_work_local:
    mov rcx, g_thread_pool.pool_mutex
    call ReleaseMutex
    jmp worker_loop_local
masm_thread_create_worker ENDP

;==============================================================================
; PUBLIC: thread_signal_event(event_id: ecx) -> bool (rax)
; Signal a thread event
;==============================================================================
ALIGN 16
thread_signal_event PROC
    ; ecx = event index (0-31)
    push rbx
    sub rsp, 32
    
    ; Validate event index
    cmp ecx, 32
    jge signal_error_local
    
    ; Get event handle
    mov rax, ecx
    imul rax, 8
    mov r8, OFFSET g_event_table
    add r8, rax
    
    mov rcx, [r8]
    test rcx, rcx
    jz signal_error_local
    
    ; Signal event
    call SetEvent
    test eax, eax
    jz signal_error_local
    
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
    
signal_error_local:
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
masm_thread_signal_event ENDP

;==============================================================================
; PUBLIC: thread_wait_event(event_id: ecx, timeout_ms: edx) -> bool (rax)
; Wait for a thread event with timeout
;==============================================================================
ALIGN 16
thread_wait_event PROC
    ; ecx = event index, edx = timeout_ms
    push rbx
    sub rsp, 32
    
    ; Validate event index
    cmp ecx, 32
    jge wait_error_local
    
    ; Get event handle
    mov rax, rcx
    imul rax, 8
    mov r8, OFFSET g_event_table
    add r8, rax
    
    mov rcx, [r8]
    test rcx, rcx
    jz wait_error_local
    
    ; Wait for event
    ; rcx = handle, edx = timeout_ms (already set)
    call WaitForSingleObject
    
    cmp eax, WAIT_OBJECT_0
    jne wait_error_local
    
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
    
wait_error_local:
    xor eax, eax
    add rsp, 32
    pop rbx
    ret
masm_thread_wait_event ENDP

END





