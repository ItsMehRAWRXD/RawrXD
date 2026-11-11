; ==============================================================================
; Sovereign_Telemetry_API.asm — Standalone telemetry + threading exports
; ==============================================================================
; Extracted from Sovereign_Unified_Entry.asm for DLL linkage.
; No main() — pure library functions.
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN GetCurrentThread     : PROC
EXTERN SetThreadAffinityMask : PROC

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Latency ring buffer (64 slots)
LatencyBuffer   dq 64 dup(0)
LatencyHead     dq 0
LatencyTail     dq 0

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; PIN_THREAD: Bind current thread to specified core
; RCX = AffinityMask (1 << coreIndex)
; ==============================================================================
PUBLIC PIN_THREAD
PIN_THREAD PROC
    push rcx
    call GetCurrentThread
    mov rcx, rax
    pop rdx
    call SetThreadAffinityMask
    ret
PIN_THREAD ENDP

; ==============================================================================
; READ_LATENCY: Seqlock Implementation
; Ensures consistency without locking or heavy atomics
; Returns: RAX = latest latency in cycles, 0 if empty
; ==============================================================================
PUBLIC READ_LATENCY
READ_LATENCY PROC
    push rbx
    push r8
rl_retry:
    mov rbx, [LatencyTail]      ; Snapshot Tail
    mov r8, [LatencyHead]       ; Snapshot Head
    cmp rbx, r8
    je rl_empty                 ; Buffer empty

    ; Read the data
    mov rax, [LatencyBuffer + rbx*8]

    ; Verify Tail hasn't changed (The Seqlock Check)
    cmp rbx, [LatencyTail]
    jne rl_retry                ; Writer changed tail, data is inconsistent

    ; Advance Tail
    inc rbx
    and rbx, 63                 ; Wrap 64
    mov [LatencyTail], rbx      ; Commit

    pop r8
    pop rbx
    ret

rl_empty:
    xor rax, rax
    pop r8
    pop rbx
    ret
READ_LATENCY ENDP

; ==============================================================================
; WRITE_LATENCY: Push latency to ring buffer
; RCX = Latency in cycles
; ==============================================================================
PUBLIC WRITE_LATENCY
WRITE_LATENCY PROC
    push rbx
    push rsi

    mov rbx, LatencyHead
    mov rsi, rbx
    inc rsi
    and rsi, 63

    ; Check full
    cmp rsi, LatencyTail
    je wl_skip

    ; Write
    mov LatencyBuffer[rbx * 8], rcx

    ; Advance
    mov LatencyHead, rsi

wl_skip:
    pop rsi
    pop rbx
    ret
WRITE_LATENCY ENDP

end
