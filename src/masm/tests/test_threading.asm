;=====================================================================
; test_threading.asm - Unit tests for MASM Threading & Thread Pool
;=====================================================================

include asm_sync.inc

; External dependencies
EXTERN asm_thread_pool_create:PROC
EXTERN asm_thread_pool_enqueue:PROC
EXTERN asm_thread_pool_destroy:PROC
EXTERN asm_log:PROC
EXTERN ExitProcess:PROC

.data
    test_msg_start    db "Starting Threading Tests...", 10, 0
    test_msg_mutex    db "Testing Mutex...", 0
    test_msg_pool     db "Testing Thread Pool...", 0
    test_msg_done     db "Threading Tests Complete.", 10, 0
    test_msg_ok       db " [OK]", 10, 0
    test_msg_fail     db " [FAIL]", 10, 0
    
    counter           dq 0
    pool_handle       dq 0
    mutex_handle      dq 0

.code

; Task procedure for thread pool test
ALIGN 16
test_task PROC
    push rbx
    mov rbx, rcx            ; context = mutex handle
    
    ; Lock mutex
    mov rcx, rbx
    call asm_mutex_lock
    
    ; Increment counter atomically (or just under lock)
    lea rax, counter
    inc qword ptr [rax]
    
    ; Unlock mutex
    mov rcx, rbx
    call asm_mutex_unlock
    
    pop rbx
    ret
test_task ENDP

main PROC
    sub rsp, 40
    
    ; Log start
    lea rcx, test_msg_start
    call asm_log
    
    ; 1. Test Mutex
    lea rcx, test_msg_mutex
    call asm_log
    
    call asm_mutex_create
    mov mutex_handle, rax
    test rax, rax
    jz mutex_fail
    
    mov rcx, rax
    call asm_mutex_lock
    mov rcx, mutex_handle
    call asm_mutex_unlock
    
    lea rcx, test_msg_ok
    call asm_log
    
    ; 2. Test Thread Pool
    lea rcx, test_msg_pool
    call asm_log
    
    mov rcx, 4              ; 4 threads
    call asm_thread_pool_create
    mov pool_handle, rax
    test rax, rax
    jz pool_fail
    
    ; Enqueue 100 tasks
    mov rbx, 100
enqueue_loop:
    test rbx, rbx
    jz wait_tasks
    
    mov rcx, pool_handle
    lea rdx, test_task
    mov r8, mutex_handle
    call asm_thread_pool_enqueue
    
    dec rbx
    jmp enqueue_loop

wait_tasks:
    ; Sleep for a bit to let threads work
    ; In real test, use an event to signal completion
    mov rcx, 1000           ; 1 second
    ; call Sleep (need to extern it)
    
    ; Check counter
    mov rax, counter
    cmp rax, 100
    jne pool_fail
    
    lea rcx, test_msg_ok
    call asm_log
    
    ; Cleanup
    mov rcx, pool_handle
    call asm_thread_pool_destroy
    
    mov rcx, mutex_handle
    call asm_mutex_destroy
    
    lea rcx, test_msg_done
    call asm_log
    
    xor ecx, ecx
    call ExitProcess

mutex_fail:
    lea rcx, test_msg_fail
    call asm_log
    mov ecx, 1
    call ExitProcess

pool_fail:
    lea rcx, test_msg_fail
    call asm_log
    mov ecx, 1
    call ExitProcess

main ENDP

END

