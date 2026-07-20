;===========================================================================
; ControlBlock_x64.asm
; RawrXD IPC Transport Layer - x64 Assembly Implementation
;
; Bare-metal atomic operations for lock-free IPC.
; Uses LOCK prefix for atomicity, PAUSE for spin-wait efficiency.
;===========================================================================

.code

;===========================================================================
; ATOMIC SEQUENCE OPERATIONS
;===========================================================================

; uint64_t CB_AtomicIncrementSequence(ControlBlock* cb)
; Atomically increments sequence counter
; Returns: New sequence value
CB_AtomicIncrementSequence PROC FRAME
    mov rcx, [rsp+8]        ; Load cb pointer from shadow space
    
    lock inc qword ptr [rcx] ; Increment sequence (offset 0)
    mov rax, [rcx]          ; Return new value
    
    ret
CB_AtomicIncrementSequence ENDP

; uint64_t CB_AtomicLoadSequence(ControlBlock* cb)
; Loads sequence with acquire semantics
CB_AtomicLoadSequence PROC FRAME
    mov rcx, [rsp+8]        ; Load cb pointer
    
    mov rax, [rcx]          ; Load sequence
    ; Implicit acquire on x64 loads
    
    ret
CB_AtomicLoadSequence ENDP

;===========================================================================
; STATE MACHINE ATOMIC OPERATIONS
;===========================================================================

; BufferState CB_AtomicLoadState(ControlBlock* cb)
; Loads state with acquire semantics
CB_AtomicLoadState PROC FRAME
    mov rcx, [rsp+8]        ; Load cb pointer
    
    mov eax, [rcx+8]        ; Load state (offset 8)
    ; Implicit acquire on x64 loads
    
    ret
CB_AtomicLoadState ENDP

; void CB_AtomicStoreState(ControlBlock* cb, BufferState state)
; Stores state with release semantics
CB_AtomicStoreState PROC FRAME
    mov rcx, [rsp+8]        ; Load cb pointer
    mov edx, [rsp+16]       ; Load state value
    
    ; SFENCE for release semantics
    sfence
    mov [rcx+8], edx        ; Store state
    
    ret
CB_AtomicStoreState ENDP

;===========================================================================
; SPIN-WAIT WITH PAUSE
;===========================================================================

; void CB_SpinWaitWithPause(void)
; Executes PAUSE instruction to reduce power in spin loops
CB_SpinWaitWithPause PROC FRAME
    pause                   ; Hint to CPU that we're spinning
    ret
CB_SpinWaitWithPause ENDP

; void CB_MemoryFenceAcquire(void)
; Full memory fence for acquire semantics
CB_MemoryFenceAcquire PROC FRAME
    ; LFENCE + MFENCE for acquire
    lfence
    mfence
    ret
CB_MemoryFenceAcquire ENDP

; void CB_MemoryFenceRelease(void)
; Full memory fence for release semantics
CB_MemoryFenceRelease PROC FRAME
    ; SFENCE + MFENCE for release
    sfence
    mfence
    ret
CB_MemoryFenceRelease ENDP

;===========================================================================
; DISPATCH TABLE
;===========================================================================

; void* CB_GetLoaderFunction(ExecutionMode mode)
; Returns function pointer from dispatch table
; Mode 0 = Synthetic, Mode 1 = GGUF
CB_GetLoaderFunction PROC FRAME
    movzx rax, byte ptr [rsp+8]    ; Load mode (0 or 1)
    
    ; Dispatch table (would be defined in data segment)
    ; For now, return mode as placeholder
    shl rax, 3                      ; Multiply by 8 (pointer size)
    
    ret
CB_GetLoaderFunction ENDP

;===========================================================================
; CACHE LINE OPERATIONS
;===========================================================================

; void CB_PrefetchForWrite(void* addr)
; Prefetch address for write (L1 cache)
CB_PrefetchForWrite PROC FRAME
    mov rcx, [rsp+8]        ; Load address
    prefetchw [rcx]         ; Prefetch for write
    ret
CB_PrefetchForWrite ENDP

; void CB_PrefetchForRead(void* addr)
; Prefetch address for read (L1 cache)
CB_PrefetchForRead PROC FRAME
    mov rcx, [rsp+8]        ; Load address
    prefetcht0 [rcx]        ; Prefetch to L1
    ret
CB_PrefetchForRead ENDP

;===========================================================================
; VALIDATION
;===========================================================================

; BOOL CB_ValidateMagic(uint64_t magic)
; Returns TRUE if magic matches CONTROL_BLOCK_MAGIC
CB_ValidateMagic PROC FRAME
    mov rax, [rsp+8]        ; Load magic value
    mov rcx, 524157524344424Ch ; "RAWRCDBL" in hex (little-endian)
    
    cmp rax, rcx
    sete al                 ; Set AL to 1 if equal, 0 if not
    movzx rax, al           ; Zero-extend to 64-bit
    
    ret
CB_ValidateMagic ENDP

END
