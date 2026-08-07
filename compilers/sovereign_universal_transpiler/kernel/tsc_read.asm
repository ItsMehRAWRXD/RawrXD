; ============================================================================
; kernel/tsc_read.asm - High-Resolution TSC (Time Stamp Counter) Read
; Returns 64-bit CPU cycle count for benchmarking precision
; ============================================================================

option casemap:none

PUBLIC ReadTSC

.code

; ============================================================================
; ReadTSC: Read CPU Time Stamp Counter
; Returns: RAX = 64-bit TSC value (CPU cycles since reset)
; Uses RDTSCP for serialized, out-of-order safe reading
; ============================================================================
ReadTSC PROC
    ; RDTSCP is a serializing instruction that waits for all prior
    ; instructions to complete before reading the counter, and prevents
    ; subsequent instructions from starting until after the read.
    ; This gives us accurate cycle measurements for benchmarking.
    
    rdtscp                    ; EDX:EAX = TSC, ECX = processor ID
    shl rdx, 32              ; Move high 32 bits to upper half of RAX
    or rax, rdx              ; Combine into 64-bit value in RAX
    ret
ReadTSC ENDP

; ============================================================================
; ReadTSC_Serialized: Fully serialized TSC read with MFENCE
; Use this when you need maximum accuracy across memory operations
; ============================================================================
ReadTSC_Serialized PROC
    mfence                    ; Ensure all memory ops complete
    rdtscp                    ; Serialized TSC read
    shl rdx, 32
    or rax, rdx
    ret
ReadTSC_Serialized ENDP

; ============================================================================
; ReadTSC_Start: Begin benchmark timing (serialized)
; ============================================================================
ReadTSC_Start PROC
    mfence
    rdtscp
    shl rdx, 32
    or rax, rdx
    ret
ReadTSC_Start ENDP

; ============================================================================
; ReadTSC_End: End benchmark timing (serialized)
; Returns RAX = TSC delta (end - start)
; RCX = start TSC value (passed in)
; ============================================================================
ReadTSC_End PROC
    mfence
    rdtscp
    shl rdx, 32
    or rax, rdx
    sub rax, rcx              ; RAX = delta cycles
    ret
ReadTSC_End ENDP

END
