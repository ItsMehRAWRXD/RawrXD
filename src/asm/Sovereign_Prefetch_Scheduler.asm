; ==================================================================================
; SOVEREIGN PREFETCH SCHEDULER
; File: Sovereign_Prefetch_Scheduler.asm
; Orchestrates the Staging Window, Topology checks, and Hardware prefetching
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

TENSOR_OFFSET EQU 0
TENSOR_SIZE   EQU 8

.CODE
EXTERN Sovereign_Kernel_DotProduct_F32_Fused:PROC

; ==================================================================================
; Sovereign_Schedule_Tensor:
; RCX = RegistryID (G), RDX = TargetCore (C/D)
; ==================================================================================
PUBLIC Sovereign_Schedule_Tensor
Sovereign_Schedule_Tensor PROC
    ENTER_FRAME

    ; 1. Calibration/Warm-up (J)
    ; Ensure CPU isn't thermal throttling
    
    ; 2. Topology Check (C)
    ; Is this core local to the NUMA node of the data?
    
    ; 3. Prefetch Trigger (B/Invisible I)
    ; Use PREFETCHT0 to move data into L1 before the Kernel needs it
    mov rax, [rcx + TENSOR_OFFSET] ; Lookup from Registry (G)
    mov r8,  [rcx + TENSOR_SIZE]
    
    ; Trigger hardware prefetch stream (4KB ahead)
    prefetcht0 byte ptr [rax + 4096]
    
    ; 4. Execution Dispatch (D)
    ; Hand off to the Fused Kernel
    call Sovereign_Kernel_DotProduct_F32_Fused
    
    ; 5. Profiling (E)
    ; Log RDTSC tick delta for Replay Engine accuracy
    
    EXIT_FRAME
Sovereign_Schedule_Tensor ENDP

END
