;=============================================================================
; Jukebox Worker - VAL-030.1 MASM Implementation
; The mechanical heart of B008 streaming
;
; This is the IOCP worker thread that moves blocks from disk to RAM.
; No C++ runtime. No dependencies. Just Win32 primitives.
;
; Entry: JukeboxWorkerAsm
; Parameters:
;   RCX = HANDLE hIOCP (I/O Completion Port)
;   RDX = ControlBlock* (Jukebox control structure)
;=============================================================================

.code

;-----------------------------------------------------------------------------
; JukeboxWorkerAsm
; Main worker loop - blocks on IOCP, processes completions
;-----------------------------------------------------------------------------
JukeboxWorkerAsm PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40                 ; Shadow space + alignment
    .allocstack 40
    .endprolog

    mov     rbx, rdx                ; RBX = ControlBlock pointer
    mov     rsi, rcx                ; RSI = hIOCP

.loop:
    ; Check shutdown flag
    mov     eax, [rbx + 88]         ; ControlBlock::shutdown (offset 88)
    test    eax, eax
    jnz     .shutdown

    ; Setup for GetQueuedCompletionStatus
    ; Parameters: hIOCP, &bytes, &key, &overlapped, timeout
    lea     r9, [rsp + 32]          ; pOverlapped (local buffer)
    lea     r8, [rsp + 24]          ; pBytesTransferred
    lea     rdx, [rsp + 16]         ; pCompletionKey
    mov     rcx, rsi                ; hIOCP
    mov     r10, -1                 ; INFINITE timeout

    ; Call GetQueuedCompletionStatus
    mov     rax, QWORD PTR [GetQueuedCompletionStatus]
    call    rax

    ; Check result
    test    eax, eax
    jz      .error_or_shutdown

    ; Success - process completion
    ; Completion key = block_id
    mov     rax, [rsp + 16]         ; Load completion key (block_id)
    mov     rdx, rbx                ; ControlBlock pointer

    ; Call C++ handler to mark block ready
    ; void JukeboxMarkBlockReady(ControlBlock* control, uint64_t block_id)
    mov     rcx, rbx
    mov     rdx, rax
    call    JukeboxMarkBlockReady

    ; Get next request from queue and issue read
    mov     rcx, rbx
    call    IssueNextRequest

    jmp     .loop

.error_or_shutdown:
    ; Check if it's a real error or just shutdown
    call    GetLastError
    cmp     eax, ERROR_ABANDONED_WAIT_0
    je      .shutdown

    ; Real error - log and continue
    jmp     .loop

.shutdown:
    ; Cleanup and exit
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret

JukeboxWorkerAsm ENDP

;-----------------------------------------------------------------------------
; IssueNextRequest
; Get next request from queue and issue async read
; Parameters: RCX = ControlBlock*
;-----------------------------------------------------------------------------
IssueNextRequest PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rbx, rcx                ; RBX = ControlBlock

    ; Call C++ PopRequest
    ; bool PopRequest(Request& out)
    lea     rdx, [rsp + 32]         ; Local Request buffer
    call    QWORD PTR [PopRequestPtr]

    test    al, al
    jz      .no_request             ; Queue empty

    ; Issue async read
    ; Setup ReadFile parameters
    mov     rcx, [rbx]              ; ControlBlock::hFile
    lea     rdx, [rsp + 32]         ; Request buffer
    mov     r8, [rdx + 16]          ; Request::buffer_slot
    xor     r9, r9                  ; lpNumberOfBytesRead (async)
    lea     rax, [rdx + 24]         ; Request::overlapped
    mov     [rsp + 32], rax         ; lpOverlapped

    call    QWORD PTR [ReadFilePtr]

    test    eax, eax
    jnz     .success

    ; Check for ERROR_IO_PENDING (expected for async)
    call    GetLastError
    cmp     eax, ERROR_IO_PENDING
    je      .success

    ; Real error
    jmp     .error

.success:
    ; Increment in-flight counter
    lock inc DWORD PTR [rbx + 72]   ; ControlBlock::current_queue_depth

.no_request:
.error:
    add     rsp, 40
    pop     rsi
    pop     rbx
    ret

IssueNextRequest ENDP

;-----------------------------------------------------------------------------
; Data Section
;-----------------------------------------------------------------------------
.data

; Function pointers (filled by C++ initialization)
PopRequestPtr       QWORD   0
ReadFilePtr         QWORD   0

;-----------------------------------------------------------------------------
; Exports
;-----------------------------------------------------------------------------
PUBLIC JukeboxWorkerAsm
PUBLIC IssueNextRequest

end
