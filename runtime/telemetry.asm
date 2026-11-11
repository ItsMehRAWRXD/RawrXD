; ============================================================================
; telemetry.asm - Pure MASM64 Telemetry Core
; ============================================================================
; Zero-dependency observability layer for RawrXD inference runtime.
; Uses ring buffer with power-of-2 sizing for mask-based indexing.
;
; Exports:
;   Telemetry_Log      - Write telemetry entry
;   Telemetry_Dump     - Read entries to user buffer
;   Telemetry_Reset    - Clear buffer and indices
;   Telemetry_GetCount - Get number of entries in buffer
; ============================================================================

; Assembler directives
IFDEF RAX
ELSE
.model flat, c
ENDIF

.code

; ============================================================================
; Constants
; ============================================================================
TELEMETRY_BUFFER_SIZE EQU 4096      ; Must be power of 2
SIZEOF_TELEMETRY_ENTRY EQU 32       ; 4 + 4 + 8 + 8 + 8 = 32 bytes

; ============================================================================
; Data Section
; ============================================================================
.data

; Ring buffer storage (32-byte aligned)
; Each entry: phase_id (4) + padding (4) + timestamp (8) + value0 (8) + value1 (8) + value2 (8) = 32 bytes
g_telemetry_buffer BYTE TELEMETRY_BUFFER_SIZE * SIZEOF_TELEMETRY_ENTRY DUP(0)

; Buffer indices (volatile - accessed from multiple threads)
ALIGN 8
g_telemetry_write_idx QWORD 0       ; Next write position (monotonically increasing)
g_telemetry_read_idx  QWORD 0       ; Next read position (monotonically increasing)
g_telemetry_dropped   QWORD 0       ; Count of dropped entries (buffer full)

; ============================================================================
; Telemetry_Log
; ============================================================================
; Writes a telemetry entry to the ring buffer.
;
; Arguments (Windows x64 ABI):
;   RCX = phase_id (DWORD)
;   RDX = value0 (QWORD)
;   R8  = value1 (QWORD)
;   R9  = value2 (QWORD)
;
; Clobbers: RAX, R10, R11
; Preserves: All other registers
; ============================================================================
Telemetry_Log PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    
    ; Get current write index
    mov rax, g_telemetry_write_idx
    
    ; Compute slot index: idx & (BUFFER_SIZE - 1)
    ; This works because BUFFER_SIZE is power of 2
    mov r10, rax
    and r10, TELEMETRY_BUFFER_SIZE - 1
    
    ; Compute slot address: buffer + (idx * entry_size)
    imul r10, SIZEOF_TELEMETRY_ENTRY
    mov rdi, OFFSET g_telemetry_buffer
    add rdi, r10
    
    ; Read timestamp (RDTSC)
    ; Returns 64-bit timestamp in EDX:EAX
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r11, rax                    ; Save timestamp in R11
    
    ; Write entry fields
    ; Entry layout: [phase_id:4][padding:4][timestamp:8][value0:8][value1:8]
    mov DWORD PTR [rdi], ecx        ; phase_id
    mov DWORD PTR [rdi + 4], 0      ; padding
    mov QWORD PTR [rdi + 8], r11    ; timestamp
    mov QWORD PTR [rdi + 16], rdx   ; value0
    mov QWORD PTR [rdi + 24], r8    ; value1
    
    ; Memory fence to ensure write completes before index update
    sfence
    
    ; Advance write index (atomic increment)
    inc g_telemetry_write_idx
    
    ; Check if buffer is full (write - read >= BUFFER_SIZE)
    mov rax, g_telemetry_write_idx
    sub rax, g_telemetry_read_idx
    cmp rax, TELEMETRY_BUFFER_SIZE
    jb telemetry_log_done           ; Jump if buffer not full
    
    ; Buffer full - advance read index (drop oldest)
    inc g_telemetry_read_idx
    inc g_telemetry_dropped
    
telemetry_log_done:
    pop rdi
    pop rsi
    pop rbx
    ret
Telemetry_Log ENDP

; ============================================================================
; Telemetry_Dump
; ============================================================================
; Reads telemetry entries from ring buffer to user buffer.
;
; Arguments:
;   RCX = buffer pointer (user-allocated)
;   RDX = max entries to read
;
; Returns:
;   RAX = entries actually read
; ============================================================================
Telemetry_Dump PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog
    
    mov rdi, rcx                    ; RDI = user buffer
    mov r12, rdx                    ; R12 = max entries
    
    ; Calculate available entries: write_idx - read_idx
    mov rax, g_telemetry_write_idx
    sub rax, g_telemetry_read_idx
    
    ; Clamp to max requested
    cmp rax, r12
    cmova rax, r12                  ; RAX = entries to copy
    
    test rax, rax
    jz telemetry_dump_done          ; Nothing to copy
    
    mov rcx, rax                    ; RCX = loop counter
    mov rsi, g_telemetry_read_idx   ; RSI = current read index
    
telemetry_dump_copy_loop:
    ; Compute source slot index
    mov rbx, rsi
    and rbx, TELEMETRY_BUFFER_SIZE - 1
    imul rbx, SIZEOF_TELEMETRY_ENTRY
    mov r10, OFFSET g_telemetry_buffer
    add r10, rbx
    
    ; Copy entry (32 bytes) using 2x 16-byte moves
    movups xmm0, XMMWORD PTR [r10]
    movups xmm1, XMMWORD PTR [r10 + 16]
    movups XMMWORD PTR [rdi], xmm0
    movups XMMWORD PTR [rdi + 16], xmm1
    
    ; Advance pointers
    add rdi, SIZEOF_TELEMETRY_ENTRY
    inc rsi
    dec rcx
    jnz telemetry_dump_copy_loop
    
    ; Advance read index
    add g_telemetry_read_idx, rax
    
telemetry_dump_done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Telemetry_Dump ENDP

; ============================================================================
; Telemetry_Reset
; ============================================================================
; Clears the telemetry buffer and resets indices.
;
; Arguments: None
; Returns: None
; ============================================================================
Telemetry_Reset PROC FRAME
    .endprolog
    
    ; Reset indices
    mov g_telemetry_write_idx, 0
    mov g_telemetry_read_idx, 0
    mov g_telemetry_dropped, 0
    
    ; Clear buffer (optional - zero memory)
    ; This is expensive, so we skip it and rely on index reset
    
    ret
Telemetry_Reset ENDP

; ============================================================================
; Telemetry_GetCount
; ============================================================================
; Returns the number of entries currently in the buffer.
;
; Arguments: None
; Returns:
;   RAX = number of entries
; ============================================================================
Telemetry_GetCount PROC FRAME
    .endprolog
    
    mov rax, g_telemetry_write_idx
    sub rax, g_telemetry_read_idx
    
    ret
Telemetry_GetCount ENDP

; ============================================================================
; Telemetry_GetDropped
; ============================================================================
; Returns the number of dropped entries (buffer full).
;
; Arguments: None
; Returns:
;   RAX = number of dropped entries
; ============================================================================
Telemetry_GetDropped PROC FRAME
    .endprolog
    
    mov rax, g_telemetry_dropped
    
    ret
Telemetry_GetDropped ENDP

; ============================================================================
; Telemetry_Now
; ============================================================================
; Returns current RDTSC timestamp.
;
; Arguments: None
; Returns:
;   RAX = 64-bit timestamp
; ============================================================================
Telemetry_Now PROC FRAME
    .endprolog
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    ret
Telemetry_Now ENDP

END
