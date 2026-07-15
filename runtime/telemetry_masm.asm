; ============================================================================
; MASM Telemetry Core - Zero-overhead Performance Logging
; ============================================================================
; Features:
; - Lock-free ring buffer (SPSC: single producer, single consumer)
; - RDTSC timestamps (cycle-accurate)
; - No CRT dependencies
; - x64 ABI compliant
; ============================================================================

option casemap:none

; ============================================================================
; External Functions
; ============================================================================
extrn VirtualAlloc:proc
extrn VirtualFree:proc

; ============================================================================
; Data Section
; ============================================================================
.data

; Ring buffer configuration
TELEMETRY_BUFFER_SIZE dq 1048576     ; 1MB default
TELEMETRY_BUFFER_PTR  dq 0           ; Pointer to allocated buffer
TELEMETRY_WRITE_IDX   dq 0           ; Write index (atomic)
TELEMETRY_READ_IDX    dq 0           ; Read index (atomic)
TELEMETRY_DROPPED     dq 0           ; Dropped event count
TELEMETRY_INITIALIZED db 0           ; Initialization flag

; Event structure (32 bytes)
;   timestamp:  dq (8 bytes) - RDTSC
;   phase:      dd (4 bytes) - Phase ID
;   reserved:   dd (4 bytes) - Padding
;   value0:     dq (8 bytes) - Generic value 0
;   value1:     dq (8 bytes) - Generic value 1
TELEMETRY_EVENT_SIZE equ 32

; ============================================================================
; Code Section
; ============================================================================
.code

; ----------------------------------------------------------------------------
; MasmTelemetry_Init - Initialize telemetry subsystem
; ----------------------------------------------------------------------------
; Input:  RCX = buffer size (must be power of 2)
; Output: RAX = 0 on success, non-zero on error
; ----------------------------------------------------------------------------
MasmTelemetry_Init PROC FRAME
    push rbx
    push rdi
    push rsi
    .pushreg rbx
    .pushreg rdi
    .pushreg rsi
    .endprolog
    
    ; Check if already initialized
    mov al, TELEMETRY_INITIALIZED
    test al, al
    jnz init_already_done
    
    ; Validate buffer size (must be power of 2)
    mov rbx, rcx
    dec rbx
    and rbx, rcx
    jnz init_error          ; Not power of 2
    
    ; Store buffer size
    mov TELEMETRY_BUFFER_SIZE, rcx
    
    ; Allocate buffer using VirtualAlloc
    xor ecx, ecx            ; lpAddress = NULL (let system choose)
    mov rdx, TELEMETRY_BUFFER_SIZE
    mov r8d, 00001000h      ; flAllocationType = MEM_COMMIT
    mov r9d, 04h            ; flProtect = PAGE_READWRITE
    sub rsp, 32             ; Shadow space
    call VirtualAlloc
    add rsp, 32
    
    test rax, rax
    jz init_error           ; Allocation failed
    
    ; Store buffer pointer
    mov TELEMETRY_BUFFER_PTR, rax
    
    ; Initialize indices
    mov TELEMETRY_WRITE_IDX, 0
    mov TELEMETRY_READ_IDX, 0
    mov TELEMETRY_DROPPED, 0
    
    ; Mark initialized
    mov TELEMETRY_INITIALIZED, 1
    
    xor rax, rax            ; Return 0 (success)
    jmp init_done
    
init_already_done:
    xor rax, rax            ; Already initialized = success
    jmp init_done
    
init_error:
    mov rax, 1              ; Return error
    
init_done:
    pop rsi
    pop rdi
    pop rbx
    ret
MasmTelemetry_Init ENDP

; ----------------------------------------------------------------------------
; MasmTelemetry_Shutdown - Shutdown telemetry subsystem
; ----------------------------------------------------------------------------
MasmTelemetry_Shutdown PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Check if initialized
    mov al, TELEMETRY_INITIALIZED
    test al, al
    jz shutdown_done
    
    ; Flush remaining events
    sub rsp, 32
    call MasmTelemetry_Flush
    add rsp, 32
    
    ; Free buffer
    mov rcx, TELEMETRY_BUFFER_PTR
    xor edx, edx            ; dwSize = 0 (must be 0 for MEM_RELEASE)
    mov r8d, 00008000h      ; dwFreeType = MEM_RELEASE
    sub rsp, 32
    call VirtualFree
    add rsp, 32
    
    ; Clear state
    mov TELEMETRY_BUFFER_PTR, 0
    mov TELEMETRY_WRITE_IDX, 0
    mov TELEMETRY_READ_IDX, 0
    mov TELEMETRY_INITIALIZED, 0
    
shutdown_done:
    pop rbx
    ret
MasmTelemetry_Shutdown ENDP

; ----------------------------------------------------------------------------
; MasmTelemetry_Log - Log a telemetry event
; ----------------------------------------------------------------------------
; Input:  ECX = phase ID
;         RDX = value0
;         R8  = value1
; Clobbers: RAX, R9, R10, R11
; ----------------------------------------------------------------------------
MasmTelemetry_Log PROC FRAME
    .endprolog
    
    ; Check if initialized
    mov al, TELEMETRY_INITIALIZED
    test al, al
    jz log_done             ; Silently drop if not initialized
    
    ; Get timestamp (RDTSC)
    rdtsc
    shl rdx, 32
    or rax, rdx             ; RAX = full 64-bit timestamp
    
    ; Calculate write position
    mov r9, TELEMETRY_WRITE_IDX
    mov r10, TELEMETRY_BUFFER_SIZE
    dec r10                 ; R10 = mask for modulo
    
    ; Check if buffer is full
    mov r11, TELEMETRY_READ_IDX
    sub r9, r11
    cmp r9, r10
    jae log_drop            ; Buffer full, drop event
    
    ; Get buffer pointer
    mov r11, TELEMETRY_BUFFER_PTR
    
    ; Calculate event address
    mov r9, TELEMETRY_WRITE_IDX
    and r9, r10             ; R9 = write_idx % buffer_size
    imul r9, TELEMETRY_EVENT_SIZE
    add r11, r9             ; R11 = event address
    
    ; Write event
    mov [r11], rax          ; timestamp
    mov [r11 + 8], ecx      ; phase
    mov [r11 + 16], rdx     ; value0
    mov [r11 + 24], r8      ; value1
    
    ; Increment write index
    inc TELEMETRY_WRITE_IDX
    
log_done:
    ret
    
log_drop:
    inc TELEMETRY_DROPPED
    ret
MasmTelemetry_Log ENDP

; ----------------------------------------------------------------------------
; MasmTelemetry_Rdtsc - Get current timestamp
; ----------------------------------------------------------------------------
; Output: RAX = RDTSC value
; ----------------------------------------------------------------------------
MasmTelemetry_Rdtsc PROC FRAME
    .endprolog
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
MasmTelemetry_Rdtsc ENDP

; ----------------------------------------------------------------------------
; MasmTelemetry_Flush - Flush telemetry buffer to output
; ----------------------------------------------------------------------------
; Output: RAX = Number of events flushed
; ----------------------------------------------------------------------------
MasmTelemetry_Flush PROC FRAME
    push rbx
    push rdi
    push rsi
    .pushreg rbx
    .pushreg rdi
    .pushreg rsi
    .endprolog
    
    ; Calculate number of events to flush
    mov rbx, TELEMETRY_WRITE_IDX
    mov rdi, TELEMETRY_READ_IDX
    sub rbx, rdi            ; RBX = events to flush
    
    test rbx, rbx
    jz flush_done           ; Nothing to flush
    
    ; TODO: Implement actual output (file write, shared memory, etc.)
    ; For now, just advance read index
    add TELEMETRY_READ_IDX, rbx
    
flush_done:
    mov rax, rbx            ; Return number of events flushed
    pop rsi
    pop rdi
    pop rbx
    ret
MasmTelemetry_Flush ENDP

; ----------------------------------------------------------------------------
; MasmTelemetry_GetStats - Get telemetry statistics
; ----------------------------------------------------------------------------
; Input:  RCX = pointer to TelemetryStats structure
; ----------------------------------------------------------------------------
MasmTelemetry_GetStats PROC FRAME
    .endprolog
    mov rax, TELEMETRY_WRITE_IDX
    sub rax, TELEMETRY_READ_IDX
    mov [rcx], rax          ; eventsLogged
    
    mov rax, TELEMETRY_DROPPED
    mov [rcx + 8], rax      ; eventsDropped
    
    mov rax, TELEMETRY_BUFFER_SIZE
    mov [rcx + 16], rax     ; bufferSize
    
    mov rax, TELEMETRY_WRITE_IDX
    sub rax, TELEMETRY_READ_IDX
    imul rax, TELEMETRY_EVENT_SIZE
    mov [rcx + 24], rax     ; bufferUsed
    
    ret
MasmTelemetry_GetStats ENDP

; ============================================================================
; Exports
; ============================================================================
public MasmTelemetry_Init
public MasmTelemetry_Shutdown
public MasmTelemetry_Log
public MasmTelemetry_Rdtsc
public MasmTelemetry_Flush
public MasmTelemetry_GetStats

END

END
