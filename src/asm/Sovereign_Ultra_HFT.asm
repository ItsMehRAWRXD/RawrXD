; Sovereign_HFT_Core.asm | Zero-Dependency HFT Primitives
; Target: x64 MASM | Optimized for <12ns cycle latency

.CODE

; 1. Reciprocal TPS Calculation (Eliminates DIV latency)
; RCX = Pulse_Delta, RDX = Precomputed_Reciprocal (1/Interval)
; Result (RAX) = (Pulse_Delta * Reciprocal) >> 64
ALIGN 16
PUBLIC Sovereign_Calculate_TPS_Fast
Sovereign_Calculate_TPS_Fast PROC
    mov rax, rcx        ; Move Pulse_Delta to RAX for multiplication
    mul rdx             ; RDX:RAX = RAX * RDX (Pulse_Delta * Reciprocal)
    mov rax, rdx        ; Move high-part to RAX for fixed-point result
    ret
Sovereign_Calculate_TPS_Fast ENDP

; 2. 64-Byte Slab Alignment (For vmovaps pipeline throughput)
; RCX = Requested_Size
ALIGN 16
PUBLIC Sovereign_Align_Buffer
Sovereign_Align_Buffer PROC
    mov rax, rcx
    add rax, 63         ; Add alignment slack
    and rax, -64        ; Force 64-byte boundary masking
    ret
Sovereign_Align_Buffer ENDP

; 3. Deterministic Pipeline Barrier
; Ensures no speculative execution leakage during Hot-Swap
ALIGN 16
PUBLIC Sovereign_Execution_Fence
Sovereign_Execution_Fence PROC
    lfence              ; Serialize execution
    ret
Sovereign_Execution_Fence ENDP

END
