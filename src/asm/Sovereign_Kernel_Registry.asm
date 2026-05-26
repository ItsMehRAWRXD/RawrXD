; Sovereign_Kernel_Registry.asm - The "Kernel of Kernels" Shared State Registry
; ABI: Shared context for distinct runtime subsystems
; Constraints: Zero-dependency, Cache-aligned, Lock-free communication

include Sovereign_Common.inc

.DATA
; g_SovereignRegistry is defined in Sovereign_Globals.asm


; --- Lock-Free Ring Buffer (Telemetry/Sync Hub) ---
; Designed for cross-system feedback (e.g. Network Sync -> JIT Optimizer)
ALIGN 16
TELEMETRY_RING_SIZE EQU 1024
g_TelemetryRing     QWORD TELEMETRY_RING_SIZE DUP(0)
g_RingReadIdx       QWORD 0
g_RingWriteIdx      QWORD 0

.CODE

; XR_Registry_Push_Telemetry: Lock-free push to the shared ring buffer
; RCX = Value
PUBLIC XR_Registry_Push_Telemetry
XR_Registry_Push_Telemetry PROC
    push    rbx
    push    rdx
    
    mov     rax, [g_RingWriteIdx]
_RetryPush:
    mov     rbx, rax
    inc     rbx
    and     rbx, TELEMETRY_RING_SIZE - 1
    
    ; Check if full
    cmp     rbx, [g_RingReadIdx]
    je      _BufferFull
    
    ; Atomic Exchange to secure the slot
    ; We use a simplified model here for the Sovereign kernel
    lock cmpxchg [g_RingWriteIdx], rbx
    jnz     _RetryPush
    
    ; Store data at the previous rax index
    mov     rdx, rax
    and     rdx, TELEMETRY_RING_SIZE - 1
    lea     r8, g_TelemetryRing
    mov     [r8 + rdx * 8], rcx
    
    pop     rdx
    pop     rbx
    ret

_BufferFull:
    ; Drop or stall? For high-performance inference, we drop to avoid backpressure
    pop     rdx
    pop     rbx
    ret
XR_Registry_Push_Telemetry ENDP

; XR_Registry_Pop_Telemetry: Lock-free pop from the shared ring buffer
; Returns RAX = Value, or -1 if empty
PUBLIC XR_Registry_Pop_Telemetry
XR_Registry_Pop_Telemetry PROC
    push    rbx
    
    mov     rax, [g_RingReadIdx]
_RetryPop:
    cmp     rax, [g_RingWriteIdx]
    je      _BufferEmpty
    
    mov     rbx, rax
    inc     rbx
    and     rbx, TELEMETRY_RING_SIZE - 1
    
    ; Attempt to advance read pointer
    lock cmpxchg [g_RingReadIdx], rbx
    jnz     _RetryPop
    
    ; Fetch data
    and     rax, TELEMETRY_RING_SIZE - 1
    lea     r8, g_TelemetryRing
    mov     rax, [r8 + rax * 8]
    
    pop     rbx
    ret

_BufferEmpty:
    mov     rax, -1
    pop     rbx
    ret
XR_Registry_Pop_Telemetry ENDP

END
