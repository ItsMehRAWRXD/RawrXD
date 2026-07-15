; RawrXD_Telemetry_Fixed.asm
; Fixed version with proper synchronization and cache-line alignment
; =============================================================================

; =============================================================================
; Constants
; =============================================================================

; Ring buffer configuration
TELEMETRY_BUFFER_SIZE   equ 65536     ; 64KB ring buffer
TELEMETRY_MAX_EVENTS    equ 1024      ; Max events in buffer (power of 2)
TELEMETRY_EVENT_SIZE    equ 64        ; Bytes per event (cache line)

; Metric types
METRIC_INFERENCE_START  equ 1
METRIC_INFERENCE_END    equ 2
METRIC_TOKEN_GENERATED  equ 3
METRIC_CACHE_HIT        equ 4
METRIC_CACHE_MISS       equ 5
METRIC_PRECISION_SWITCH equ 6
METRIC_SECURITY_EVENT   equ 7

; Quantization types
QUANT_INT8              equ 0
QUANT_BF16              equ 1
QUANT_FP32              equ 2

; =============================================================================
; Data Structures - Cache Line Aligned (64 bytes)
; =============================================================================

; Metric event structure (exactly 64 bytes)
METRIC_EVENT STRUCT ALIGN(64)
    timestamp       QWORD       ?       ; RDTSC timestamp (8 bytes)
    metric_type     DWORD       ?       ; Event type (4 bytes)
    session_id      DWORD       ?       ; Session identifier (4 bytes)
    token_count     DWORD       ?       ; Token count (4 bytes)
    latency_us      DWORD       ?       ; Latency in microseconds (4 bytes)
    quant_type      BYTE        ?       ; Quantization type (1 byte)
    cache_hit       BYTE        ?       ; Cache hit flag (1 byte)
    reserved        BYTE        2 DUP(?) ; Padding to 32 bytes
    ; Extended data (32 bytes)
    ext_data        QWORD       4 DUP(?) ; Extra metric data
METRIC_EVENT ENDS

; Ring buffer header (exactly 64 bytes, cache-aligned)
RING_BUFFER_HEADER STRUCT ALIGN(64)
    magic           DWORD       ?       ; 0x52415452 "RATR"
    version         DWORD       ?       ; Version 1
    ; Write index - atomic access only
    write_index     DWORD       ?       ; Current write position
    write_pad       DWORD       ?       ; Padding to 8 bytes
    ; Read index - atomic access only  
    read_index      DWORD       ?       ; Current read position
    read_pad        DWORD       ?       ; Padding to 8 bytes
    ; Statistics
    event_count     QWORD       ?       ; Total events written
    dropped_events  QWORD       ?       ; Events dropped (buffer full)
    ; Configuration
    buffer_size     DWORD       ?       ; Size of buffer
    event_size      DWORD       ?       ; Size of each event
    ; Spinlock for synchronization
    spinlock        DWORD       ?       ; 0=unlocked, 1=locked
    lock_pad        DWORD       3 DUP(?) ; Padding to 64 bytes
RING_BUFFER_HEADER ENDS

; =============================================================================
; Data Section
; =============================================================================
.data

; Shared memory name
telemetry_shm_name  db "Global\RawrXD_Telemetry_Buffer_v2", 0

; Header initialization
header_init         RING_BUFFER_HEADER <0x52415452, 1, 0, 0, 0, 0, 0, 0, TELEMETRY_BUFFER_SIZE, TELEMETRY_EVENT_SIZE, 0, <0,0,0>>

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; SpinLock_Acquire
; Acquires a spinlock with exponential backoff
; RCX = pointer to spinlock variable
; =============================================================================
SpinLock_Acquire PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx
    xor     eax, eax
    mov     edx, 1
    
.spin_loop:
    ; Try to acquire lock with cmpxchg (atomic compare-exchange)
    lock cmpxchg dword ptr [rbx], edx
    je      .acquired       ; If successful (ZF=1), lock acquired
    
    ; Spin with pause instruction (reduces power consumption)
    pause
    jmp     .spin_loop
    
.acquired:
    ; Memory barrier after acquiring lock
    mfence
    
    pop     rbx
    ret
SpinLock_Acquire ENDP

; =============================================================================
; SpinLock_Release
; Releases a spinlock
; RCX = pointer to spinlock variable
; =============================================================================
SpinLock_Release PROC FRAME
    .endprolog
    
    ; Memory barrier before releasing lock
    mfence
    
    ; Release lock
    mov     dword ptr [rcx], 0
    
    ret
SpinLock_Release ENDP

; =============================================================================
; Telemetry_Init
; Initializes the telemetry system with memory-mapped ring buffer
; Returns: RAX = pointer to mapped memory, 0 on failure
; =============================================================================
Telemetry_Init PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    ; Create file mapping
    mov     rcx, -1                 ; hFile = INVALID_HANDLE_VALUE
    xor     rdx, rdx                ; lpFileMappingAttributes = NULL
    mov     r8, 4                   ; flProtect = PAGE_READWRITE
    xor     r9, r9                  ; dwMaximumSizeHigh = 0
    mov     qword ptr [rsp+32], TELEMETRY_BUFFER_SIZE
    mov     qword ptr [rsp+40], offset telemetry_shm_name
    call    CreateFileMappingA
    
    cmp     rax, 0
    je      .init_failed
    mov     rbx, rax                ; RBX = file mapping handle
    
    ; Map view of file
    mov     rcx, rbx                ; hFileMappingObject
    mov     rdx, 0F001Fh            ; dwDesiredAccess = FILE_MAP_ALL_ACCESS
    xor     r8, r8                  ; dwFileOffsetHigh = 0
    xor     r9, r9                  ; dwFileOffsetLow = 0
    mov     qword ptr [rsp+32], 0   ; dwNumberOfBytesToMap = 0 (all)
    call    MapViewOfFile
    
    cmp     rax, 0
    je      .map_failed
    mov     rsi, rax                ; RSI = mapped memory pointer
    
    ; Initialize header with proper alignment
    mov     rdi, rsi
    lea     rdx, header_init
    mov     rcx, SIZEOF RING_BUFFER_HEADER
    call    memcpy
    
    ; Ensure spinlock is initialized to 0
    mov     dword ptr [rsi].RING_BUFFER_HEADER.spinlock, 0
    
    ; Return mapped memory pointer
    mov     rax, rsi
    jmp     .exit
    
.map_failed:
    mov     rcx, rbx
    call    CloseHandle
    
.init_failed:
    xor     rax, rax
    
.exit:
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_Init ENDP

; =============================================================================
; Telemetry_LogEvent
; Logs a metric event to the ring buffer (thread-safe)
; RCX = pointer to mapped memory
; RDX = pointer to METRIC_EVENT structure
; Returns: RAX = 1 on success, 0 on failure
; =============================================================================
Telemetry_LogEvent PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx                ; RBX = buffer pointer
    mov     r12, rdx                ; R12 = event pointer
    
    ; Acquire spinlock
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Acquire
    
    ; Get current timestamp (RDTSC)
    rdtsc
    shl     rdx, 32
    or      rax, rdx                ; RAX = 64-bit timestamp
    mov     [r12].METRIC_EVENT.timestamp, rax
    
    ; Read indices (while holding lock)
    mov     r13d, [rbx].RING_BUFFER_HEADER.write_index
    mov     esi, [rbx].RING_BUFFER_HEADER.read_index
    
    ; Calculate next write position
    mov     edi, r13d
    inc     edi
    and     edi, TELEMETRY_MAX_EVENTS - 1  ; Wrap around using mask
    
    ; Check if buffer is full (next position == read position)
    cmp     edi, esi
    je      .buffer_full
    
    ; Calculate destination address
    mov     rdi, rbx
    add     rdi, SIZEOF RING_BUFFER_HEADER
    mov     eax, r13d
    mov     ecx, TELEMETRY_EVENT_SIZE
    mul     rcx
    add     rdi, rax                ; RDI = destination address
    
    ; Copy event data using movsq for alignment safety
    mov     rsi, r12
    mov     rcx, TELEMETRY_EVENT_SIZE / 8  ; Copy 8 bytes at a time
    cld
    rep     movsq
    
    ; Update write index atomically
    mov     [rbx].RING_BUFFER_HEADER.write_index, edi
    
    ; Update event count
    inc     qword ptr [rbx].RING_BUFFER_HEADER.event_count
    
    ; Mark success
    mov     eax, 1
    jmp     .done
    
.buffer_full:
    ; Increment dropped events counter
    inc     qword ptr [rbx].RING_BUFFER_HEADER.dropped_events
    xor     eax, eax                ; Return 0 (failure)
    
.done:
    ; Release spinlock
    mov     r13, rax                ; Save return value
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Release
    mov     rax, r13                ; Restore return value
    
    add     rsp, 40
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_LogEvent ENDP

; =============================================================================
; Telemetry_ReadEvent
; Reads a metric event from the ring buffer (thread-safe)
; RCX = pointer to mapped memory
; RDX = pointer to destination METRIC_EVENT structure
; Returns: RAX = 1 on success (event read), 0 on failure (buffer empty)
; =============================================================================
Telemetry_ReadEvent PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx                ; RBX = buffer pointer
    mov     r12, rdx                ; R12 = destination pointer
    
    ; Acquire spinlock
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Acquire
    
    ; Read indices
    mov     esi, [rbx].RING_BUFFER_HEADER.read_index
    mov     edi, [rbx].RING_BUFFER_HEADER.write_index
    
    ; Check if buffer is empty
    cmp     esi, edi
    je      .buffer_empty
    
    ; Calculate source address
    mov     rsi, rbx
    add     rsi, SIZEOF RING_BUFFER_HEADER
    mov     eax, esi
    mov     ecx, TELEMETRY_EVENT_SIZE
    mul     rcx
    add     rsi, rax                ; RSI = source address
    
    ; Copy event data
    mov     rdi, r12
    mov     rcx, TELEMETRY_EVENT_SIZE / 8
    cld
    rep     movsq
    
    ; Update read index
    inc     esi
    and     esi, TELEMETRY_MAX_EVENTS - 1
    mov     [rbx].RING_BUFFER_HEADER.read_index, esi
    
    mov     eax, 1                  ; Success
    jmp     .done
    
.buffer_empty:
    xor     eax, eax                ; Return 0 (empty)
    
.done:
    ; Release spinlock
    mov     r12, rax                ; Save return value
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Release
    mov     rax, r12                ; Restore return value
    
    add     rsp, 40
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_ReadEvent ENDP

; =============================================================================
; Telemetry_GetStats
; Gets telemetry statistics (thread-safe)
; RCX = pointer to mapped memory
; RDX = pointer to stats structure
; =============================================================================
Telemetry_GetStats PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rbx, rcx
    mov     rdi, rdx
    
    ; Acquire spinlock for consistent read
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Acquire
    
    ; Copy statistics
    mov     rax, [rbx].RING_BUFFER_HEADER.event_count
    mov     [rdi], rax              ; total_events
    
    mov     rax, [rbx].RING_BUFFER_HEADER.dropped_events
    mov     [rdi+8], rax            ; dropped_events
    
    mov     eax, [rbx].RING_BUFFER_HEADER.write_index
    mov     [rdi+16], eax           ; write_index
    
    mov     eax, [rbx].RING_BUFFER_HEADER.read_index
    mov     [rdi+20], eax           ; read_index
    
    ; Release spinlock
    lea     rcx, [rbx].RING_BUFFER_HEADER.spinlock
    call    SpinLock_Release
    
    pop     rdi
    pop     rbx
    ret
Telemetry_GetStats ENDP

; =============================================================================
; Telemetry_Shutdown
; Cleans up telemetry system
; RCX = pointer to mapped memory
; =============================================================================
Telemetry_Shutdown PROC FRAME
    .endprolog
    
    ; Unmap view of file
    call    UnmapViewOfFile
    
    ret
Telemetry_Shutdown ENDP

END
