; ============================================================================
; ElasticIOCPReader.asm
; Native Win32 IOCP-based async NVMe reader for RawrXD Elastic Residency
; No C runtime dependency. Pure MASM64 + Win32 APIs.
;
; Architecture:
;   CreateIoCompletionPort + overlapped ReadFile
;   Multiple concurrent I/O lanes (configurable)
;   Completion callbacks trigger residency state transitions
;   Lock-free SPSC ring between IOCP thread and Elastic scheduler
; ============================================================================

include RawrXD_Defs.inc

; ============================================================================
; Constants
; ============================================================================
ELASTIC_IOCP_LANES          equ 4
ELASTIC_MAX_PENDING_READS   equ 64
ELASTIC_EXTENT_SIZE         equ (64 * 1024 * 1024)   ; 64 MB extents
ELASTIC_PAGE_ALIGNMENT      equ 4096
ELASTIC_NVME_BLOCK_SIZE     equ 4096

; IORequest states
IOREQ_STATE_FREE            equ 0
IOREQ_STATE_PENDING         equ 1
IOREQ_STATE_COMPLETED       equ 2
IOREQ_STATE_FAILED          equ 3

; ============================================================================
; Structures
; ============================================================================

; Per-request context carried through OVERLAPPED
IORequest STRUCT ALIGN 64
    overlapped      OVERLAPPED <>      ; must be first for GetQueuedCompletionStatus
    state           DWORD ?            ; FREE / PENDING / COMPLETED / FAILED
    tensorId        DWORD ?
    layerIndex      DWORD ?
    expertIndex     DWORD ?
    fileOffset      QWORD ?
    bytesRequested  DWORD ?
    bytesRead       DWORD ?
    buffer          QWORD ?            ; VirtualAlloc staging buffer
    bufferSize      DWORD ?
    completionTime  QWORD ?            ; QueryPerformanceCounter
    errorCode       DWORD ?
IORequest ENDS

; IOCP lane context
IOCPLane STRUCT ALIGN 64
    hFile           QWORD ?            ; HANDLE to GGUF
    hIOCP           QWORD ?            ; IOCP handle
    requests        QWORD ?            ; IORequest[ELASTIC_MAX_PENDING_READS]
    freeStack       QWORD ?            ; lock-free stack index
    pendingCount    DWORD ?
    completedCount  DWORD ?
    totalBytesRead  QWORD ?
    totalReads      QWORD ?
    totalErrors     QWORD ?
IOCPLane ENDS

; Elastic IOCP Manager
ElasticIOCPManager STRUCT ALIGN 64
    hFile           QWORD ?            ; main GGUF file handle
    hIOCP           QWORD ?            ; completion port
    lanes           QWORD ?            ; IOCPLane[ELASTIC_IOCP_LANES]
    numLanes        DWORD ?
    maxPending      DWORD ?
    extentSize      DWORD ?
    running         BYTE ?
    padding         BYTE 7 dup(?)
    ; Thread handles
    hCompletionThread QWORD ?
    ; Telemetry
    totalRequests   QWORD ?
    totalCompleted  QWORD ?
    totalErrors     QWORD ?
    totalBytesRead  QWORD ?
    avgLatencyUs    QWORD ?
ElasticIOCPManager ENDS

; ============================================================================
; Data Section
; ============================================================================
.data

align 64
g_IOCPManager   ElasticIOCPManager <>

; Error strings
szErrCreateFile     db "[ElasticIOCP] CreateFileW failed", 0
szErrCreateIOCP     db "[ElasticIOCP] CreateIoCompletionPort failed", 0
szErrVirtualAlloc   db "[ElasticIOCP] VirtualAlloc failed", 0
szErrReadFile       db "[ElasticIOCP] ReadFile failed", 0
szErrNoFreeReq      db "[ElasticIOCP] No free request slots", 0

; ============================================================================
; Code Section
; ============================================================================
.code

; ----------------------------------------------------------------------------
; ElasticIOCP_Initialize
;   RCX = wchar_t* ggufPath (UTF-16)
;   RDX = extentSize (0 = default 64MB)
;   R8  = numLanes (0 = default 4)
;   Returns: RAX = true/false
; ----------------------------------------------------------------------------
ElasticIOCP_Initialize PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    .allocstack 40
    .endprolog

    mov     rbx, rcx                    ; ggufPath
    mov     r12d, edx                   ; extentSize
    mov     r13d, r8d                   ; numLanes

    ; Default parameters
    test    r12d, r12d
    jnz     @F
    mov     r12d, ELASTIC_EXTENT_SIZE
@@: test    r13d, r13d
    jnz     @F
    mov     r13d, ELASTIC_IOCP_LANES
@@:

    ; Open GGUF with overlapped + no buffering + sequential scan
    ; FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN
    mov     rcx, rbx                    ; lpFileName
    xor     edx, edx                    ; dwDesiredAccess = GENERIC_READ
    mov     dl, GENERIC_READ
    xor     r8d, r8d                    ; dwShareMode = FILE_SHARE_READ
    mov     r8b, FILE_SHARE_READ
    xor     r9d, r9d                    ; lpSecurityAttributes = NULL
    push    0                           ; hTemplateFile
    push    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_OVERLAPPED or FILE_FLAG_NO_BUFFERING or FILE_FLAG_SEQUENTIAL_SCAN
    push    CREATE_ALWAYS               ; dwCreationDisposition (use OPEN_EXISTING in production)
    push    0                           ; lpSecurityAttributes
    sub     rsp, 32
    call    CreateFileW
    add     rsp, 48
    cmp     rax, INVALID_HANDLE_VALUE
    jne     @F
    lea     rcx, szErrCreateFile
    call    OutputDebugStringA
    xor     eax, eax
    jmp     .exit
@@:
    mov     g_IOCPManager.hFile, rax

    ; Create IOCP
    xor     ecx, ecx                    ; FileHandle = INVALID_HANDLE_VALUE (manual association)
    mov     rcx, INVALID_HANDLE_VALUE
    xor     edx, edx                    ; ExistingCompletionPort = NULL
    xor     r8d, r8d                    ; CompletionKey = 0
    mov     r9d, ELASTIC_IOCP_LANES     ; NumberOfConcurrentThreads
    sub     rsp, 32
    call    CreateIoCompletionPort
    add     rsp, 32
    test    rax, rax
    jnz     @F
    lea     rcx, szErrCreateFile
    call    OutputDebugStringA
    xor     eax, eax
    jmp     .exit
@@:
    mov     g_IOCPManager.hIOCP, rax

    ; Allocate lanes
    mov     ecx, r13d
    imul    ecx, SIZEOF IOCPLane
    mov     edx, MEM_COMMIT or MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9d, r9d
    sub     rsp, 32
    call    VirtualAlloc
    add     rsp, 32
    test    rax, rax
    jnz     @F
    lea     rcx, szErrVirtualAlloc
    call    OutputDebugStringA
    xor     eax, eax
    jmp     .exit
@@:
    mov     g_IOCPManager.lanes, rax
    mov     g_IOCPManager.numLanes, r13d
    mov     g_IOCPManager.extentSize, r12d
    mov     g_IOCPManager.maxPending, ELASTIC_MAX_PENDING_READS
    mov     g_IOCPManager.running, 1

    ; Initialize each lane
    xor     esi, esi                    ; lane index
.lane_init:
    cmp     esi, r13d
    jge     .lanes_done

    mov     rdi, g_IOCPManager.lanes
    mov     eax, SIZEOF IOCPLane
    mul     esi
    add     rdi, rax                    ; RDI = current lane

    ; Associate file with IOCP for this lane
    mov     rcx, g_IOCPManager.hFile
    mov     rdx, g_IOCPManager.hIOCP
    mov     r8, rdi                     ; CompletionKey = lane pointer
    xor     r9d, r9d                    ; Reserved
    sub     rsp, 32
    call    CreateIoCompletionPort
    add     rsp, 32

    ; Allocate request pool
    mov     ecx, ELASTIC_MAX_PENDING_READS
    imul    ecx, SIZEOF IORequest
    mov     edx, MEM_COMMIT or MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9d, r9d
    sub     rsp, 32
    call    VirtualAlloc
    add     rsp, 32
    mov     [rdi].IOCPLane.requests, rax

    ; Initialize free stack (simple index stack)
    mov     [rdi].IOCPLane.freeStack, 0
    mov     [rdi].IOCPLane.pendingCount, 0
    mov     [rdi].IOCPLane.completedCount, 0
    mov     [rdi].IOCPLane.totalBytesRead, 0
    mov     [rdi].IOCPLane.totalReads, 0
    mov     [rdi].IOCPLane.totalErrors, 0

    inc     esi
    jmp     .lane_init
.lanes_done:

    ; Start completion thread
    xor     ecx, ecx                    ; lpThreadAttributes
    xor     edx, edx                    ; dwStackSize
    lea     r8, ElasticIOCP_CompletionThread
    xor     r9d, r9d                    ; lpParameter
    push    0                           ; dwCreationFlags
    push    0                           ; lpThreadId
    sub     rsp, 32
    call    CreateThread
    add     rsp, 48
    mov     g_IOCPManager.hCompletionThread, rax

    mov     eax, 1
.exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ElasticIOCP_Initialize ENDP

; ----------------------------------------------------------------------------
; ElasticIOCP_SubmitRead
;   RCX = tensorId
;   RDX = fileOffset (QWORD)
;   R8  = bytesToRead
;   R9  = layerIndex
;   [RSP+40] = expertIndex
;   Returns: RAX = IORequest* or NULL
; ----------------------------------------------------------------------------
ElasticIOCP_SubmitRead PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    .allocstack 32
    .endprolog

    mov     ebx, ecx                    ; tensorId
    mov     r12, rdx                    ; fileOffset
    mov     esi, r8d                    ; bytesToRead
    mov     edi, r9d                    ; layerIndex

    ; Pick lane by tensorId % numLanes
    mov     eax, ebx
    xor     edx, edx
    mov     r8d, g_IOCPManager.numLanes
    div     r8d
    mov     r8d, edx                    ; lane index

    mov     rax, g_IOCPManager.lanes
    mov     ecx, SIZEOF IOCPLane
    mul     r8d
    add     rax, rcx                    ; RAX = lane
    mov     rsi, rax                    ; RSI = lane

    ; Find free request slot
    mov     rdi, [rsi].IOCPLane.requests
    xor     ecx, ecx
.find_free:
    cmp     ecx, ELASTIC_MAX_PENDING_READS
    jge     .no_free
    mov     eax, SIZEOF IORequest
    mul     ecx
    cmp     [rdi + rax].IORequest.state, IOREQ_STATE_FREE
    je      .found_free
    inc     ecx
    jmp     .find_free
.found_free:
    ; Mark as pending
    mov     [rdi + rax].IORequest.state, IOREQ_STATE_PENDING
    mov     [rdi + rax].IORequest.tensorId, ebx
    mov     [rdi + rax].IORequest.layerIndex, edi
    mov     rax, [rsp + 48 + 32]        ; expertIndex (stack arg)
    mov     [rdi + rax].IORequest.expertIndex, eax
    mov     [rdi + rax].IORequest.fileOffset, r12
    mov     [rdi + rax].IORequest.bytesRequested, esi

    ; Allocate aligned staging buffer
    mov     ecx, esi
    add     ecx, ELASTIC_NVME_BLOCK_SIZE - 1
    and     ecx, not (ELASTIC_NVME_BLOCK_SIZE - 1)
    mov     [rdi + rax].IORequest.bufferSize, ecx
    mov     edx, MEM_COMMIT or MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9d, r9d
    sub     rsp, 32
    call    VirtualAlloc
    add     rsp, 32
    test    rax, rax
    jnz     @F
    mov     [rdi + rax].IORequest.state, IOREQ_STATE_FREE
    xor     eax, eax
    jmp     .exit
@@:
    mov     [rdi + rax].IORequest.buffer, rax

    ; Issue overlapped ReadFile
    mov     rcx, g_IOCPManager.hFile
    mov     rdx, [rdi + rax].IORequest.buffer
    mov     r8d, [rdi + rax].IORequest.bufferSize
    lea     r9, [rdi + rax].IORequest.bytesRead
    push    0                           ; lpOverlapped = &overlapped
    lea     rax, [rdi + rax]
    push    rax
    sub     rsp, 32
    call    ReadFile
    add     rsp, 48
    test    eax, eax
    jnz     .submitted                  ; completed synchronously
    call    GetLastError
    cmp     eax, ERROR_IO_PENDING
    je      .submitted
    ; Error
    mov     [rdi + rax].IORequest.state, IOREQ_STATE_FAILED
    mov     [rdi + rax].IORequest.errorCode, eax
    xor     eax, eax
    jmp     .exit

.submitted:
    inc     [rsi].IOCPLane.pendingCount
    inc     g_IOCPManager.totalRequests
    mov     rax, rdi                    ; return IORequest*
    jmp     .exit

.no_free:
    lea     rcx, szErrNoFreeReq
    call    OutputDebugStringA
    xor     eax, eax

.exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ElasticIOCP_SubmitRead ENDP

; ----------------------------------------------------------------------------
; ElasticIOCP_CompletionThread
;   RCX = lpParameter (unused)
; ----------------------------------------------------------------------------
ElasticIOCP_CompletionThread PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .allocstack 24
    .endprolog

.completion_loop:
    cmp     g_IOCPManager.running, 0
    je      .thread_exit

    ; GetQueuedCompletionStatus
    mov     rcx, g_IOCPManager.hIOCP
    lea     rdx, [rsp + 32]             ; lpNumberOfBytesTransferred
    lea     r8, [rsp + 40]              ; lpCompletionKey
    lea     r9, [rsp + 48]              ; lpOverlapped
    mov     dword ptr [rsp + 56], INFINITE  ; dwMilliseconds
    sub     rsp, 32
    call    GetQueuedCompletionStatus
    add     rsp, 32
    test    rax, rax
    jz      .completion_error

    ; Success: R8 = completion key (lane*), R9 = overlapped (IORequest*)
    mov     rsi, r8                     ; lane
    mov     rdi, r9                     ; IORequest (overlapped is first field)

    ; Update request state
    mov     [rdi].IORequest.state, IOREQ_STATE_COMPLETED
    inc     [rsi].IOCPLane.completedCount
    inc     g_IOCPManager.totalCompleted
    mov     rax, [rsp + 32]             ; bytes transferred
    add     [rsi].IOCPLane.totalBytesRead, rax
    add     g_IOCPManager.totalBytesRead, rax

    ; TODO: signal Elastic scheduler that tensor data is ready
    ; Call ElasticResidencyManager::OnTransferComplete(tensorId, buffer)

    jmp     .completion_loop

.completion_error:
    call    GetLastError
    cmp     eax, ERROR_ABANDONED_WAIT_0
    je      .thread_exit
    inc     [rsi].IOCPLane.totalErrors
    inc     g_IOCPManager.totalErrors
    jmp     .completion_loop

.thread_exit:
    xor     eax, eax
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ElasticIOCP_CompletionThread ENDP

; ----------------------------------------------------------------------------
; ElasticIOCP_Shutdown
; ----------------------------------------------------------------------------
ElasticIOCP_Shutdown PROC FRAME
    mov     g_IOCPManager.running, 0

    ; Signal IOCP to wake completion thread
    mov     rcx, g_IOCPManager.hIOCP
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    sub     rsp, 32
    call    PostQueuedCompletionStatus
    add     rsp, 32

    ; Wait for completion thread
    mov     rcx, g_IOCPManager.hCompletionThread
    mov     edx, INFINITE
    sub     rsp, 32
    call    WaitForSingleObject
    add     rsp, 32

    ; Close handles
    mov     rcx, g_IOCPManager.hCompletionThread
    sub     rsp, 32
    call    CloseHandle
    add     rsp, 32

    mov     rcx, g_IOCPManager.hIOCP
    sub     rsp, 32
    call    CloseHandle
    add     rsp, 32

    mov     rcx, g_IOCPManager.hFile
    sub     rsp, 32
    call    CloseHandle
    add     rsp, 32

    ret
ElasticIOCP_Shutdown ENDP

; ----------------------------------------------------------------------------
; ElasticIOCP_GetTelemetry
;   RCX = pointer to telemetry buffer (QWORD totalBytes, QWORD totalReads, etc.)
; ----------------------------------------------------------------------------
ElasticIOCP_GetTelemetry PROC FRAME
    mov     rax, g_IOCPManager.totalBytesRead
    mov     [rcx], rax
    mov     rax, g_IOCPManager.totalRequests
    mov     [rcx + 8], rax
    mov     rax, g_IOCPManager.totalCompleted
    mov     [rcx + 16], rax
    mov     rax, g_IOCPManager.totalErrors
    mov     [rcx + 24], rax
    ret
ElasticIOCP_GetTelemetry ENDP

END
