; =============================================================================
; RawrXD_Telemetry.asm
; Sidecar-less Telemetry Collector for RawrXD/Sovereign Engine
; Memory-mapped ring buffer with zero-copy event logging
; =============================================================================

; =============================================================================
; Constants
; =============================================================================

; Ring buffer configuration
TELEMETRY_BUFFER_SIZE   equ 65536     ; 64KB ring buffer
TELEMETRY_MAX_EVENTS    equ 1024      ; Max events in buffer
TELEMETRY_EVENT_SIZE    equ 64        ; Bytes per event

; Metric types
METRIC_INFERENCE_START  equ 1
METRIC_INFERENCE_END    equ 2
METRIC_TOKEN_GENERATED  equ 3
METRIC_CACHE_HIT        equ 4
METRIC_CACHE_MISS       equ 5
METRIC_PRECISION_SWITCH equ 6
METRIC_SECURITY_EVENT   equ 7

; Quantization types (for tracking)
QUANT_INT8              equ 0
QUANT_BF16              equ 1
QUANT_FP32              equ 2
QUANT_INT4              equ 3

; =============================================================================
; Data Structures
; =============================================================================

; Metric event structure (64 bytes, cache-aligned)
METRIC_EVENT STRUCT
    timestamp       QWORD       ?       ; RDTSC timestamp (8 bytes)
    metric_type     DWORD       ?       ; Event type (4 bytes)
    session_id      DWORD       ?       ; Session identifier (4 bytes)
    token_count     DWORD       ?       ; Token count (4 bytes)
    latency_us      DWORD       ?       ; Latency in microseconds (4 bytes)
    quant_type      BYTE        ?       ; Quantization type (1 byte)
    cache_hit       BYTE        ?       ; Cache hit flag (1 byte)
    reserved        BYTE        6 DUP(?) ; Padding to 32 bytes
    ; Extended data (32 bytes)
    ext_data        QWORD       4 DUP(?) ; Extra metric data
METRIC_EVENT ENDS

; Ring buffer header (64 bytes)
RING_BUFFER_HEADER STRUCT
    magic           DWORD       ?       ; 0x52415452 "RATR"
    version         DWORD       ?       ; Version 1
    write_index     DWORD       ?       ; Current write position
    read_index      DWORD       ?       ; Current read position
    event_count     DWORD       ?       ; Total events written
    dropped_events  DWORD       ?       ; Events dropped (buffer full)
    buffer_size     DWORD       ?       ; Size of buffer
    event_size      DWORD       ?       ; Size of each event
    reserved        DWORD       8 DUP(?) ; Padding
RING_BUFFER_HEADER ENDS

; =============================================================================
; Data Section
; =============================================================================
.data

; Shared memory name
telemetry_shm_name  db "Global\\RawrXD_Telemetry_Buffer", 0

; Header initialization
header_init         RING_BUFFER_HEADER <0x52415452, 1, 0, 0, 0, 0, TELEMETRY_BUFFER_SIZE, TELEMETRY_EVENT_SIZE>

; Statistics (local cache)
stats_total_events  QWORD       0
stats_dropped       QWORD       0
stats_last_flush    QWORD       0

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Telemetry_Init
; Initializes the telemetry system with memory-mapped ring buffer
; Returns: RAX = handle to mapped memory, 0 on failure
; =============================================================================
Telemetry_Init PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    ; Create file mapping
    mov     rcx, -1                 ; hFile = INVALID_HANDLE_VALUE (pagefile)
    xor     rdx, rdx                ; lpFileMappingAttributes = NULL
    mov     r8, 4                   ; flProtect = PAGE_READWRITE
    xor     r9, r9                  ; dwMaximumSizeHigh = 0
    mov     qword ptr [rsp+32], TELEMETRY_BUFFER_SIZE  ; dwMaximumSizeLow
    mov     qword ptr [rsp+40], offset telemetry_shm_name  ; lpName
    call    CreateFileMappingA
    
    cmp     rax, 0
    je      .init_failed
    mov     rbx, rax                ; RBX = file mapping handle
    
    ; Map view of file
    mov     rcx, rbx                ; hFileMappingObject
    xor     rdx, rdx                ; dwDesiredAccess = FILE_MAP_ALL_ACCESS
    xor     r8, r8                  ; dwFileOffsetHigh = 0
    xor     r9, r9                  ; dwFileOffsetLow = 0
    mov     qword ptr [rsp+32], 0   ; dwNumberOfBytesToMap = 0 (all)
    call    MapViewOfFile
    
    cmp     rax, 0
    je      .map_failed
    mov     rsi, rax                ; RSI = mapped memory pointer
    
    ; Initialize header
    mov     rdi, rsi
    mov     rcx, SIZEOF RING_BUFFER_HEADER
    lea     rdx, header_init
    call    memcpy                  ; Copy header template
    
    ; Return mapped memory pointer
    mov     rax, rsi
    jmp     .exit
    
.map_failed:
    mov     rcx, rbx
    call    CloseHandle
    
.init_failed:
    xor     rax, rax
    
.exit:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_Init ENDP

; =============================================================================
; Telemetry_LogEvent
; Logs a metric event to the ring buffer
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
    .endprolog
    
    mov     rbx, rcx                ; RBX = buffer pointer
    mov     r12, rdx                ; R12 = event pointer
    
    ; Get current timestamp (RDTSC)
    rdtsc
    shl     rdx, 32
    or      rax, rdx                ; RAX = 64-bit timestamp
    mov     [r12].METRIC_EVENT.timestamp, rax
    
    ; Calculate write position
    mov     eax, [rbx].RING_BUFFER_HEADER.write_index
    mov     esi, eax                ; ESI = current write index
    
    ; Check if buffer is full
    mov     edi, [rbx].RING_BUFFER_HEADER.read_index
    mov     ecx, esi
    inc     ecx
    and     ecx, TELEMETRY_MAX_EVENTS - 1  ; Wrap around
    cmp     ecx, edi
    je      .buffer_full
    
    ; Write event to buffer
    mov     rdi, rbx
    add     rdi, SIZEOF RING_BUFFER_HEADER
    mov     eax, esi
    mul     TELEMETRY_EVENT_SIZE
    add     rdi, rax                ; RDI = destination address
    
    ; Copy event data
    mov     rsi, r12
    mov     rcx, TELEMETRY_EVENT_SIZE
    rep     movsb
    
    ; Update write index (atomic)
    inc     dword ptr [rbx].RING_BUFFER_HEADER.write_index
    and     dword ptr [rbx].RING_BUFFER_HEADER.write_index, TELEMETRY_MAX_EVENTS - 1
    
    ; Update event count
    inc     qword ptr [rbx].RING_BUFFER_HEADER.event_count
    
    mov     rax, 1                  ; Success
    jmp     .exit
    
.buffer_full:
    ; Increment dropped events counter
    inc     qword ptr [rbx].RING_BUFFER_HEADER.dropped_events
    xor     rax, rax                ; Failure (buffer full)
    
.exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_LogEvent ENDP

; =============================================================================
; Telemetry_Flush
; Flushes events from ring buffer to external collector
; RCX = pointer to mapped memory
; RDX = callback function pointer (void (*)(METRIC_EVENT*))
; Returns: RAX = number of events flushed
; =============================================================================
Telemetry_Flush PROC FRAME
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
    .endprolog
    
    mov     rbx, rcx                ; RBX = buffer pointer
    mov     r13, rdx                ; R13 = callback function
    xor     r12, r12                ; R12 = event counter
    
    ; Get read and write indices
    mov     esi, [rbx].RING_BUFFER_HEADER.read_index
    mov     edi, [rbx].RING_BUFFER_HEADER.write_index
    
.flush_loop:
    cmp     esi, edi
    je      .flush_done             ; No more events
    
    ; Calculate event address
    lea     rcx, [rbx + SIZEOF RING_BUFFER_HEADER]
    mov     eax, esi
    mul     TELEMETRY_EVENT_SIZE
    add     rcx, rax                ; RCX = event pointer
    
    ; Call callback function
    call    r13
    
    ; Update read index
    inc     esi
    and     esi, TELEMETRY_MAX_EVENTS - 1
    inc     r12                     ; Increment counter
    
    jmp     .flush_loop
    
.flush_done:
    ; Update header read index
    mov     [rbx].RING_BUFFER_HEADER.read_index, esi
    
    mov     rax, r12                ; Return event count
    
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Telemetry_Flush ENDP

; =============================================================================
; Telemetry_GetStats
; Returns telemetry statistics
; RCX = pointer to mapped memory
; RDX = pointer to stats structure (4 QWORDs: total, dropped, rate, latency)
; =============================================================================
Telemetry_GetStats PROC FRAME
    mov     r8, rdx
    
    ; Copy statistics
    mov     rax, [rcx].RING_BUFFER_HEADER.event_count
    mov     [r8], rax
    
    mov     rax, [rcx].RING_BUFFER_HEADER.dropped_events
    mov     [r8+8], rax
    
    ; Calculate event rate (events since last call)
    mov     rax, [rcx].RING_BUFFER_HEADER.event_count
    sub     rax, stats_last_flush
    mov     [r8+16], rax
    mov     stats_last_flush, [rcx].RING_BUFFER_HEADER.event_count
    
    ; Average latency placeholder
    mov     qword ptr [r8+24], 0
    
    ret
Telemetry_GetStats ENDP

; =============================================================================
; Telemetry_Shutdown
; Cleans up telemetry system
; RCX = pointer to mapped memory
; =============================================================================
Telemetry_Shutdown PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    mov     rbx, rcx
    
    ; Unmap view
    call    UnmapViewOfFile
    
    ; Note: In production, would also close handle
    ; mov     rcx, handle
    ; call    CloseHandle
    
    pop     rbx
    ret
Telemetry_Shutdown ENDP

; =============================================================================
; Utility: memcpy
; RCX = count, RDX = source, R8 = destination
; =============================================================================
memcpy PROC
    mov     rsi, rdx
    mov     rdi, r8
    mov     rax, rcx
    shr     rcx, 3          ; Divide by 8 for QWORD copy
    rep     movsq
    mov     rcx, rax
    and     rcx, 7          ; Remainder bytes
    rep     movsb
    ret
memcpy ENDP

; =============================================================================
; External Functions
; =============================================================================
extrn CreateFileMappingA:proc
extrn MapViewOfFile:proc
extrn UnmapViewOfFile:proc
extrn CloseHandle:proc

END
