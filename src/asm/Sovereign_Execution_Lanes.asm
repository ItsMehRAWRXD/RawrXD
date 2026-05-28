; ==============================================================================
; SOVEREIGN EXECUTION LANES
; File: Sovereign_Execution_Lanes.asm
; Role: Static Partitioned Execution Matrix (Zero Buffer, Zero Allocation)
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

; 64-Byte Cache-Line Aligned Lane Context
; Prevents false-sharing L3 cache invalidation across physical cores
LANE_CONTEXT STRUCT
    KernelPtr      QWORD ?
    InputBase      QWORD ?
    OutputBase     QWORD ?
    StepSize       QWORD ?
    State          QWORD ?
    Padding1       QWORD ?
    Padding2       QWORD ?
    Padding3       QWORD ?
LANE_CONTEXT ENDS

.DATA
    ALIGN 64
    g_LaneTable     LANE_CONTEXT 256 DUP(<0>)  ; Safe scaling ceiling for physical NUMA cores
    g_LaneCount     QWORD 0

.CODE

; ==============================================================================
; Sovereign_Lane_Worker
; RCX = lane context pointer (Usually pinned to a locked hardware thread)
; ==============================================================================
PUBLIC Sovereign_Lane_Worker
Sovereign_Lane_Worker PROC
    push rbx
    push rsi
    push rdi

@@Loop:
    mov rbx, rcx                 ; RBX = lane context pointer

    ; Fetch kernel
    mov rax, [rbx + LANE_CONTEXT.KernelPtr]
    test rax, rax
    jz @@Done                    ; Exit on trap/halt state
    
    ; Load physical Arena buffers
    mov rsi, [rbx + LANE_CONTEXT.InputBase]
    mov rdi, [rbx + LANE_CONTEXT.OutputBase]
    mov r8,  [rbx + LANE_CONTEXT.StepSize]

    ; Execute kernel directly (Zero Overhead)
    ; AVX-512 FMA Kernel Signature: RCX=Input, RDX=Output, R8=StepSize
    mov rcx, rsi
    mov rdx, rdi
    call rax

    ; Advance stream pointer (No rings, no middle layer)
    ; Overwrites old physical space organically sliding the window forward
    mov r8, [rbx + LANE_CONTEXT.StepSize]
    add [rbx + LANE_CONTEXT.InputBase], r8
    add [rbx + LANE_CONTEXT.OutputBase], r8

    ; Restore lane context pointer into RCX for loop continuity
    mov rcx, rbx
    jmp @@Loop

@@Done:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Lane_Worker ENDP

; ==============================================================================
; Sovereign_Stream_Dispatch
; Fires off execution across the actively constructed lanes
; ==============================================================================
PUBLIC Sovereign_Stream_Dispatch
Sovereign_Stream_Dispatch PROC
    push rdi
    push rbx
    ENTER_FRAME

    xor rdi, rdi
@@NextLane:
    cmp rdi, [g_LaneCount]
    jge @@Done

    ; sizeof(LANE_CONTEXT) = 64 bytes. shl rbx, 6 is exactly x64 multiplier.
    mov rbx, rdi
    shl rbx, 6
    
    lea rcx, [g_LaneTable]
    add rcx, rbx

    ; Dispatch to physical worker lane
    ; In the affine threading map, this is hooked per OS-thread entry
    call Sovereign_Lane_Worker

    inc rdi
    jmp @@NextLane

@@Done:
    EXIT_FRAME
    pop rbx
    pop rdi
    ret
Sovereign_Stream_Dispatch ENDP

; ==============================================================================
; Sovereign_Arena_ResetLane
; Hard reset guard to prevent pointer leaks
; ==============================================================================
PUBLIC Sovereign_Arena_ResetLane
Sovereign_Arena_ResetLane PROC
    mov qword ptr [rcx + LANE_CONTEXT.InputBase], 0
    mov qword ptr [rcx + LANE_CONTEXT.OutputBase], 0
    ret
Sovereign_Arena_ResetLane ENDP

END
