;==============================================================================
; Phase 3: Threading System - Complete MASM Implementation
; ==============================================================================
; Target: 3,300-4,500 LOC (Very High Complexity)
; Features: Thread creation, thread pools, synchronization primitives
; Dependencies: Foundation, Event system
; ==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==============================================================================
; CONSTANTS
;==============================================================================

MAX_THREADS                EQU 64
MAX_WORK_QUEUE_SIZE        EQU 1024
THREAD_STACK_SIZE          EQU 65536
THREAD_PRIORITY_NORMAL     EQU 0
THREAD_PRIORITY_LOW        EQU -2
THREAD_PRIORITY_HIGH       EQU 2

; Thread states
THREAD_STATE_INITIALIZED   EQU 0
THREAD_STATE_RUNNING       EQU 1
THREAD_STATE_STOPPED       EQU 2
THREAD_STATE_ERROR         EQU 3

; Work item priorities
WORK_PRIORITY_LOW          EQU 0
WORK_PRIORITY_NORMAL       EQU 1
WORK_PRIORITY_HIGH         EQU 2
WORK_PRIORITY_CRITICAL     EQU 3

;==============================================================================
; STRUCTURES
;==============================================================================

; Thread control block
THREAD_CONTROL_BLOCK STRUCT
    thread_handle      QWORD ?
    thread_id          DWORD ?
    thread_state       DWORD ?
    thread_func        QWORD ?
    thread_param       QWORD ?
    thread_exit_code   DWORD ?
    thread_mutex       QWORD ?
    thread_event       QWORD ?
    thread_name        QWORD ?
    thread_stack       QWORD ?
THREAD_CONTROL_BLOCK ENDS

; Work queue item
WORK_QUEUE_ITEM STRUCT
    work_func          QWORD ?
    work_param         QWORD ?
    work_priority      DWORD ?
    work_completed     DWORD ?
    work_result        QWORD ?
    work_callback      QWORD ?
    work_callback_param QWORD ?
WORK_QUEUE_ITEM ENDS

; Thread pool
THREAD_POOL STRUCT
    pool_handle        QWORD ?
    thread_count       DWORD ?
    active_threads     DWORD ?
    max_threads        DWORD ?
    min_threads        DWORD ?
    work_queue         QWORD ?
    queue_size         DWORD ?
    queue_count        DWORD ?
    queue_mutex        QWORD ?
    work_available     QWORD ?
    shutdown_event     QWORD ?
    pool_state         DWORD ?
THREAD_POOL ENDS

; Mutex
MUTEX STRUCT
    mutex_handle       QWORD ?
    owner_thread       DWORD ?
    lock_count         DWORD ?
    recursive          DWORD ?
MUTEX ENDS

; Semaphore
SEMAPHORE STRUCT
    semaphore_handle   QWORD ?
    max_count          DWORD ?
    current_count      DWORD ?
SEMAPHORE ENDS

; Event
EVENT STRUCT
    event_handle       QWORD ?
    manual_reset       DWORD ?
    signaled           DWORD ?
EVENT ENDS

;==============================================================================
; GLOBAL DATA
;==============================================================================

.data

; Thread pool global instance
g_thread_pool THREAD_POOL {}

; Thread registry
g_thread_registry QWORD MAX_THREADS DUP(0)
g_thread_count DWORD 0

; Synchronization primitives
g_global_mutex QWORD 0
g_thread_mutex QWORD 0

; Error tracking
g_last_thread_error DWORD 0

;==============================================================================
; EXTERNAL DECLARATIONS
;==============================================================================

EXTERN CreateThread:PROC
EXTERN ExitThread:PROC
EXTERN TerminateThread:PROC
EXTERN GetCurrentThreadId:PROC
EXTERN GetThreadId:PROC
EXTERN ResumeThread:PROC
EXTERN SuspendThread:PROC
EXTERN SetThreadPriority:PROC
EXTERN GetThreadPriority:PROC
EXTERN WaitForSingleObject:PROC
EXTERN WaitForMultipleObjects:PROC
EXTERN CreateMutexA:PROC
EXTERN ReleaseMutex:PROC
EXTERN CreateSemaphoreA:PROC
EXTERN ReleaseSemaphore:PROC
EXTERN CreateEventA:PROC
EXTERN SetEvent:PROC
EXTERN ResetEvent:PROC
EXTERN CloseHandle:PROC
EXTERN GetLastError:PROC
EXTERN SetLastError:PROC
EXTERN Sleep:PROC
EXTERN GetTickCount:PROC
EXTERN InterlockedIncrement:PROC
EXTERN InterlockedDecrement:PROC
EXTERN InterlockedCompareExchange:PROC

;==============================================================================
; THREAD CREATION AND MANAGEMENT
;==============================================================================

.code

;------------------------------------------------------------------------------
; thread_create - Create a new thread
; Input: RCX = thread function, RDX = parameter, R8 = thread name
; Output: RAX = thread handle, 0 on error
;------------------------------------------------------------------------------
PUBLIC thread_create
thread_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h ; Shadow space + locals
    
    ; Save parameters
    mov [rbp-8], rcx   ; thread_func
    mov [rbp-16], rdx  ; thread_param
    mov [rbp-24], r8   ; thread_name
    
    ; Create thread
    xor r9, r9         ; Stack size (default)
    xor r8, r8         ; Creation flags (0 = run immediately)
    mov rdx, rcx       ; Start address
    mov rcx, [rbp-16]  ; Parameter
    call CreateThread
    
    ; Check for error
    test rax, rax
    jz thread_create_error
    
    ; Add to registry
    call _add_thread_to_registry
    
thread_create_exit:
    add rsp, 40h
    pop rbp
    ret
    
thread_create_error:
    call GetLastError
    mov g_last_thread_error, eax
    xor rax, rax
    jmp thread_create_exit
thread_create ENDP

;------------------------------------------------------------------------------
; thread_join - Wait for thread to complete
; Input: RCX = thread handle
; Output: RAX = exit code, 0 on error
;------------------------------------------------------------------------------
PUBLIC thread_join
thread_join PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Wait for thread
    mov rdx, -1        ; INFINITE timeout
    call WaitForSingleObject
    
    ; Get exit code
    mov rcx, [rbp+16]  ; thread handle
    call GetExitCodeThread
    
    add rsp, 20h
    pop rbp
    ret
thread_join ENDP

;------------------------------------------------------------------------------
; thread_terminate - Force terminate thread
; Input: RCX = thread handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC thread_terminate
thread_terminate PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Terminate thread
    mov rdx, 1         ; Exit code
    call TerminateThread
    
    ; Check result
    test rax, rax
    jz thread_terminate_error
    
    ; Remove from registry
    call _remove_thread_from_registry
    
    mov rax, 1
    jmp thread_terminate_exit
    
thread_terminate_error:
    call GetLastError
    mov g_last_thread_error, eax
    xor rax, rax
    
thread_terminate_exit:
    add rsp, 20h
    pop rbp
    ret
thread_terminate ENDP

;------------------------------------------------------------------------------
; thread_get_current_id - Get current thread ID
; Output: RAX = thread ID
;------------------------------------------------------------------------------
PUBLIC thread_get_current_id
thread_get_current_id PROC
    call GetCurrentThreadId
    ret
thread_get_current_id ENDP

;==============================================================================
; THREAD POOL IMPLEMENTATION
;==============================================================================

;------------------------------------------------------------------------------
; thread_pool_create - Create thread pool
; Input: RCX = min threads, RDX = max threads
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC thread_pool_create
thread_pool_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Validate parameters
    cmp ecx, 1
    jl thread_pool_create_error
    cmp edx, MAX_THREADS
    jg thread_pool_create_error
    cmp ecx, edx
    jg thread_pool_create_error
    
    ; Initialize thread pool structure
    mov g_thread_pool.min_threads, ecx
    mov g_thread_pool.max_threads, edx
    mov g_thread_pool.thread_count, 0
    mov g_thread_pool.active_threads, 0
    mov g_thread_pool.pool_state, THREAD_STATE_INITIALIZED
    
    ; Create synchronization objects
    call _create_pool_sync_objects
    test rax, rax
    jz thread_pool_create_error
    
    ; Create work queue
    call _create_work_queue
    test rax, rax
    jz thread_pool_create_error
    
    ; Create worker threads
    call _create_worker_threads
    test rax, rax
    jz thread_pool_create_error
    
    mov rax, 1
    jmp thread_pool_create_exit
    
thread_pool_create_error:
    call _cleanup_thread_pool
    xor rax, rax
    
thread_pool_create_exit:
    add rsp, 40h
    pop rbp
    ret
thread_pool_create ENDP

;------------------------------------------------------------------------------
; thread_pool_queue_work - Queue work to thread pool
; Input: RCX = work function, RDX = parameter, R8 = priority
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC thread_pool_queue_work
thread_pool_queue_work PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Validate thread pool
    cmp g_thread_pool.pool_state, THREAD_STATE_RUNNING
    jne thread_pool_queue_error
    
    ; Acquire queue mutex
    mov rcx, g_thread_pool.queue_mutex
    call _acquire_mutex
    test rax, rax
    jz thread_pool_queue_error
    
    ; Check queue capacity
    mov eax, g_thread_pool.queue_count
    cmp eax, g_thread_pool.queue_size
    jge thread_pool_queue_full
    
    ; Add work item to queue
    call _add_work_item
    test rax, rax
    jz thread_pool_queue_error
    
    ; Signal work available
    mov rcx, g_thread_pool.work_available
    call SetEvent
    
    ; Release mutex
    mov rcx, g_thread_pool.queue_mutex
    call _release_mutex
    
    mov rax, 1
    jmp thread_pool_queue_exit
    
thread_pool_queue_full:
    ; Release mutex
    mov rcx, g_thread_pool.queue_mutex
    call _release_mutex
    
thread_pool_queue_error:
    xor rax, rax
    
thread_pool_queue_exit:
    add rsp, 40h
    pop rbp
    ret
thread_pool_queue_work ENDP

;------------------------------------------------------------------------------
; thread_pool_shutdown - Shutdown thread pool
; Input: None
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC thread_pool_shutdown
thread_pool_shutdown PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Set shutdown flag
    mov g_thread_pool.pool_state, THREAD_STATE_STOPPED
    
    ; Signal shutdown event
    mov rcx, g_thread_pool.shutdown_event
    call SetEvent
    
    ; Wait for all threads to exit
    call _wait_for_threads_exit
    
    ; Cleanup resources
    call _cleanup_thread_pool
    
    mov rax, 1
    add rsp, 20h
    pop rbp
    ret
thread_pool_shutdown ENDP

;==============================================================================
; SYNCHRONIZATION PRIMITIVES
;==============================================================================

;------------------------------------------------------------------------------
; mutex_create - Create mutex
; Input: RCX = recursive flag (0=non-recursive, 1=recursive)
; Output: RAX = mutex handle, 0 on error
;------------------------------------------------------------------------------
PUBLIC mutex_create
mutex_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Create mutex
    xor rdx, rdx       ; No name
    xor r8, r8         ; Not initially owned
    call CreateMutexA
    
    add rsp, 20h
    pop rbp
    ret
mutex_create ENDP

;------------------------------------------------------------------------------
; mutex_lock - Lock mutex
; Input: RCX = mutex handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC mutex_lock
mutex_lock PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Wait for mutex
    mov rdx, -1        ; INFINITE timeout
    call WaitForSingleObject
    
    ; Check result
    cmp eax, WAIT_OBJECT_0
    jne mutex_lock_error
    
    mov rax, 1
    jmp mutex_lock_exit
    
mutex_lock_error:
    xor rax, rax
    
mutex_lock_exit:
    add rsp, 20h
    pop rbp
    ret
mutex_lock ENDP

;------------------------------------------------------------------------------
; mutex_unlock - Unlock mutex
; Input: RCX = mutex handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC mutex_unlock
mutex_unlock PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Release mutex
    call ReleaseMutex
    
    ; Check result
    test rax, rax
    jz mutex_unlock_error
    
    mov rax, 1
    jmp mutex_unlock_exit
    
mutex_unlock_error:
    xor rax, rax
    
mutex_unlock_exit:
    add rsp, 20h
    pop rbp
    ret
mutex_unlock ENDP

;------------------------------------------------------------------------------
; semaphore_create - Create semaphore
; Input: RCX = initial count, RDX = maximum count
; Output: RAX = semaphore handle, 0 on error
;------------------------------------------------------------------------------
PUBLIC semaphore_create
semaphore_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Create semaphore
    xor r9, r9         ; No name
    mov r8, rdx        ; Maximum count
    mov rdx, rcx       ; Initial count
    call CreateSemaphoreA
    
    add rsp, 20h
    pop rbp
    ret
semaphore_create ENDP

;------------------------------------------------------------------------------
; semaphore_acquire - Acquire semaphore
; Input: RCX = semaphore handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC semaphore_acquire
semaphore_acquire PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Wait for semaphore
    mov rdx, -1        ; INFINITE timeout
    call WaitForSingleObject
    
    ; Check result
    cmp eax, WAIT_OBJECT_0
    jne semaphore_acquire_error
    
    mov rax, 1
    jmp semaphore_acquire_exit
    
semaphore_acquire_error:
    xor rax, rax
    
semaphore_acquire_exit:
    add rsp, 20h
    pop rbp
    ret
semaphore_acquire ENDP

;------------------------------------------------------------------------------
; semaphore_release - Release semaphore
; Input: RCX = semaphore handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC semaphore_release
semaphore_release PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Release semaphore
    mov rdx, 1         ; Release count
    xor r8, r8         ; Previous count (optional)
    call ReleaseSemaphore
    
    ; Check result
    test rax, rax
    jz semaphore_release_error
    
    mov rax, 1
    jmp semaphore_release_exit
    
semaphore_release_error:
    xor rax, rax
    
semaphore_release_exit:
    add rsp, 20h
    pop rbp
    ret
semaphore_release ENDP

;------------------------------------------------------------------------------
; event_create - Create event
; Input: RCX = manual reset flag (0=auto, 1=manual)
; Output: RAX = event handle, 0 on error
;------------------------------------------------------------------------------
PUBLIC event_create
event_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Create event
    xor rdx, rdx       ; No name
    mov r8, rcx        ; Manual reset flag
    xor r9, r9         ; Initially non-signaled
    call CreateEventA
    
    add rsp, 20h
    pop rbp
    ret
event_create ENDP

;------------------------------------------------------------------------------
; event_set - Set event to signaled state
; Input: RCX = event handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC event_set
event_set PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Set event
    call SetEvent
    
    ; Check result
    test rax, rax
    jz event_set_error
    
    mov rax, 1
    jmp event_set_exit
    
event_set_error:
    xor rax, rax
    
event_set_exit:
    add rsp, 20h
    pop rbp
    ret
event_set ENDP

;------------------------------------------------------------------------------
; event_reset - Reset event to non-signaled state
; Input: RCX = event handle
; Output: RAX = success (1) or failure (0)
;------------------------------------------------------------------------------
PUBLIC event_reset
event_reset PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Reset event
    call ResetEvent
    
    ; Check result
    test rax, rax
    jz event_reset_error
    
    mov rax, 1
    jmp event_reset_exit
    
event_reset_error:
    xor rax, rax
    
event_reset_exit:
    add rsp, 20h
    pop rbp
    ret
event_reset ENDP

;------------------------------------------------------------------------------
; event_wait - Wait for event
; Input: RCX = event handle, RDX = timeout (ms, -1=infinite)
; Output: RAX = success (1) or timeout (0)
;------------------------------------------------------------------------------
PUBLIC event_wait
event_wait PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Wait for event
    call WaitForSingleObject
    
    ; Check result
    cmp eax, WAIT_OBJECT_0
    jne event_wait_timeout
    
    mov rax, 1
    jmp event_wait_exit
    
event_wait_timeout:
    xor rax, rax
    
event_wait_exit:
    add rsp, 20h
    pop rbp
    ret
event_wait ENDP

;==============================================================================
; INTERNAL HELPER FUNCTIONS
;==============================================================================

; Add thread to registry
_add_thread_to_registry PROC
    push rbp
    mov rbp, rsp
    
    ; Acquire thread registry mutex
    mov rcx, g_thread_mutex
    call _acquire_mutex
    
    ; Find empty slot
    mov ecx, 0
    mov rdx, offset g_thread_registry
    
add_thread_loop:
    cmp ecx, MAX_THREADS
    jge add_thread_full
    
    cmp qword ptr [rdx+rcx*8], 0
    je add_thread_found
    
    inc ecx
    jmp add_thread_loop
    
add_thread_found:
    ; Store thread handle
    mov [rdx+rcx*8], rax
    inc g_thread_count
    
add_thread_full:
    ; Release mutex
    mov rcx, g_thread_mutex
    call _release_mutex
    
    pop rbp
    ret
_add_thread_to_registry ENDP

; Remove thread from registry
_remove_thread_from_registry PROC
    push rbp
    mov rbp, rsp
    
    ; Acquire thread registry mutex
    mov rcx, g_thread_mutex
    call _acquire_mutex
    
    ; Find thread
    mov ecx, 0
    mov rdx, offset g_thread_registry
    mov r8, [rbp+16]   ; thread handle
    
remove_thread_loop:
    cmp ecx, MAX_THREADS
    jge remove_thread_done
    
    cmp [rdx+rcx*8], r8
    je remove_thread_found
    
    inc ecx
    jmp remove_thread_loop
    
remove_thread_found:
    ; Clear slot
    mov qword ptr [rdx+rcx*8], 0
    dec g_thread_count
    
remove_thread_done:
    ; Release mutex
    mov rcx, g_thread_mutex
    call _release_mutex
    
    pop rbp
    ret
_remove_thread_from_registry ENDP

; Create pool synchronization objects
_create_pool_sync_objects PROC
    push rbp
    mov rbp, rsp
    
    ; Create queue mutex
    mov rcx, 0         ; Non-recursive
    call mutex_create
    mov g_thread_pool.queue_mutex, rax
    test rax, rax
    jz create_sync_error
    
    ; Create work available event
    mov rcx, 0         ; Auto-reset
    call event_create
    mov g_thread_pool.work_available, rax
    test rax, rax
    jz create_sync_error
    
    ; Create shutdown event
    mov rcx, 1         ; Manual reset
    call event_create
    mov g_thread_pool.shutdown_event, rax
    test rax, rax
    jz create_sync_error
    
    mov rax, 1
    jmp create_sync_exit
    
create_sync_error:
    call _cleanup_sync_objects
    xor rax, rax
    
create_sync_exit:
    pop rbp
    ret
_create_pool_sync_objects ENDP

; Create work queue
_create_work_queue PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Allocate work queue
    mov ecx, MAX_WORK_QUEUE_SIZE
    imul ecx, sizeof WORK_QUEUE_ITEM
    call asm_malloc
    test rax, rax
    jz create_queue_error
    
    mov g_thread_pool.work_queue, rax
    mov g_thread_pool.queue_size, MAX_WORK_QUEUE_SIZE
    mov g_thread_pool.queue_count, 0
    
    mov rax, 1
    jmp create_queue_exit
    
create_queue_error:
    xor rax, rax
    
create_queue_exit:
    add rsp, 20h
    pop rbp
    ret
_create_work_queue ENDP

; Create worker threads
_create_worker_threads PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Create minimum number of threads
    mov ecx, g_thread_pool.min_threads
    mov edx, offset _worker_thread_proc
    xor r8, r8         ; No parameter
    
create_workers_loop:
    test ecx, ecx
    jz create_workers_done
    
    call thread_create
    test rax, rax
    jz create_workers_error
    
    dec ecx
    jmp create_workers_loop
    
create_workers_error:
    xor rax, rax
    jmp create_workers_exit
    
create_workers_done:
    mov rax, 1
    
create_workers_exit:
    add rsp, 20h
    pop rbp
    ret
_create_worker_threads ENDP

; Worker thread procedure
_worker_thread_proc PROC
    push rbp
    mov rbp, rsp
    
worker_thread_loop:
    ; Wait for work or shutdown
    mov rcx, 2
    mov rdx, offset g_thread_pool.work_available
    mov r8, offset g_thread_pool.shutdown_event
    mov r9, -1         ; INFINITE timeout
    call WaitForMultipleObjects
    
    ; Check if shutdown
    cmp eax, WAIT_OBJECT_0 + 1
    je worker_thread_shutdown
    
    ; Get work from queue
    call _get_work_item
    test rax, rax
    jz worker_thread_loop
    
    ; Execute work
    mov rcx, [rax+WORK_QUEUE_ITEM.work_param]
    call [rax+WORK_QUEUE_ITEM.work_func]
    
    ; Mark work as completed
    mov [rax+WORK_QUEUE_ITEM.work_completed], 1
    mov [rax+WORK_QUEUE_ITEM.work_result], rax
    
    ; Call callback if provided
    mov rcx, [rax+WORK_QUEUE_ITEM.work_callback]
    test rcx, rcx
    jz worker_thread_loop
    
    mov rdx, [rax+WORK_QUEUE_ITEM.work_callback_param]
    mov r8, [rax+WORK_QUEUE_ITEM.work_result]
    call rcx
    
    jmp worker_thread_loop
    
worker_thread_shutdown:
    pop rbp
    mov eax, 0         ; Exit code
    ret
_worker_thread_proc ENDP

; Add work item to queue
_add_work_item PROC
    push rbp
    mov rbp, rsp
    
    ; Find empty slot
    mov ecx, 0
    mov rdx, g_thread_pool.work_queue
    
add_work_loop:
    cmp ecx, g_thread_pool.queue_size
    jge add_work_full
    
    cmp dword ptr [rdx+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_completed], 0
    je add_work_found
    
    inc ecx
    jmp add_work_loop
    
add_work_found:
    ; Fill work item
    mov r8, [rbp+16]   ; work_func
    mov [rdx+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_func], r8
    mov r8, [rbp+24]   ; work_param
    mov [rdx+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_param], r8
    mov r8d, [rbp+32]  ; work_priority
    mov [rdx+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_priority], r8d
    mov dword ptr [rdx+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_completed], 0
    
    inc g_thread_pool.queue_count
    mov rax, rdx
    add rax, ecx
    imul ecx, sizeof WORK_QUEUE_ITEM
    
    jmp add_work_exit
    
add_work_full:
    xor rax, rax
    
add_work_exit:
    pop rbp
    ret
_add_work_item ENDP

; Get work item from queue
_get_work_item PROC
    push rbp
    mov rbp, rsp
    
    ; Acquire queue mutex
    mov rcx, g_thread_pool.queue_mutex
    call _acquire_mutex
    test rax, rax
    jz get_work_error
    
    ; Find highest priority work
    mov ecx, 0
    mov edx, -1        ; Best priority index
    mov r8d, WORK_PRIORITY_LOW ; Best priority value
    mov r9, g_thread_pool.work_queue
    
get_work_loop:
    cmp ecx, g_thread_pool.queue_size
    jge get_work_done
    
    ; Check if work is available and not completed
    cmp dword ptr [r9+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_completed], 0
    jne get_work_next
    
    cmp dword ptr [r9+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_func], 0
    je get_work_next
    
    ; Compare priority
    mov r10d, [r9+ecx*sizeof WORK_QUEUE_ITEM+WORK_QUEUE_ITEM.work_priority]
    cmp r10d, r8d
    jle get_work_next
    
    mov r8d, r10d
    mov edx, ecx
    
get_work_next:
    inc ecx
    jmp get_work_loop
    
get_work_done:
    ; Check if work found
    cmp edx, -1
    je get_work_empty
    
    ; Return work item
    mov rax, r9
    add rax, edx
    imul edx, sizeof WORK_QUEUE_ITEM
    
    jmp get_work_exit
    
get_work_empty:
    xor rax, rax
    
get_work_exit:
    ; Release mutex
    mov rcx, g_thread_pool.queue_mutex
    call _release_mutex
    
    pop rbp
    ret
_get_work_item ENDP

; Wait for all threads to exit
_wait_for_threads_exit PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Wait for each thread
    mov ecx, 0
    mov rdx, offset g_thread_registry
    
wait_threads_loop:
    cmp ecx, MAX_THREADS
    jge wait_threads_done
    
    cmp qword ptr [rdx+ecx*8], 0
    je wait_threads_next
    
    mov rcx, [rdx+ecx*8]
    call thread_join
    
wait_threads_next:
    inc ecx
    jmp wait_threads_loop
    
wait_threads_done:
    add rsp, 20h
    pop rbp
    ret
_wait_for_threads_exit ENDP

; Cleanup thread pool resources
_cleanup_thread_pool PROC
    push rbp
    mov rbp, rsp
    
    ; Cleanup synchronization objects
    call _cleanup_sync_objects
    
    ; Free work queue
    mov rcx, g_thread_pool.work_queue
    test rcx, rcx
    jz cleanup_queue_done
    call asm_free
    
cleanup_queue_done:
    ; Reset thread pool state
    mov g_thread_pool.pool_state, THREAD_STATE_STOPPED
    mov g_thread_pool.thread_count, 0
    mov g_thread_pool.active_threads, 0
    mov g_thread_pool.queue_count, 0
    
    pop rbp
    ret
_cleanup_thread_pool ENDP

; Cleanup synchronization objects
_cleanup_sync_objects PROC
    push rbp
    mov rbp, rsp
    
    ; Close queue mutex
    mov rcx, g_thread_pool.queue_mutex
    test rcx, rcx
    jz cleanup_mutex_done
    call CloseHandle
    
cleanup_mutex_done:
    ; Close work available event
    mov rcx, g_thread_pool.work_available
    test rcx, rcx
    jz cleanup_work_done
    call CloseHandle
    
cleanup_work_done:
    ; Close shutdown event
    mov rcx, g_thread_pool.shutdown_event
    test rcx, rcx
    jz cleanup_shutdown_done
    call CloseHandle
    
cleanup_shutdown_done:
    pop rbp
    ret
_cleanup_sync_objects ENDP

; Acquire mutex (internal)
_acquire_mutex PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    mov rdx, -1        ; INFINITE timeout
    call WaitForSingleObject
    
    cmp eax, WAIT_OBJECT_0
    jne acquire_mutex_error
    
    mov rax, 1
    jmp acquire_mutex_exit
    
acquire_mutex_error:
    xor rax, rax
    
acquire_mutex_exit:
    add rsp, 20h
    pop rbp
    ret
_acquire_mutex ENDP

; Release mutex (internal)
_release_mutex PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    call ReleaseMutex
    
    test rax, rax
    jz release_mutex_error
    
    mov rax, 1
    jmp release_mutex_exit
    
release_mutex_error:
    xor rax, rax
    
release_mutex_exit:
    add rsp, 20h
    pop rbp
    ret
_release_mutex ENDP

;==============================================================================
; EXPORTED FUNCTION TABLE
;==============================================================================

; Thread management
PUBLIC thread_create
PUBLIC thread_join
PUBLIC thread_terminate
PUBLIC thread_get_current_id

; Thread pool
PUBLIC thread_pool_create
PUBLIC thread_pool_queue_work
PUBLIC thread_pool_shutdown

; Synchronization
PUBLIC mutex_create
PUBLIC mutex_lock
PUBLIC mutex_unlock
PUBLIC semaphore_create
PUBLIC semaphore_acquire
PUBLIC semaphore_release
PUBLIC event_create
PUBLIC event_set
PUBLIC event_reset
PUBLIC event_wait

.end
