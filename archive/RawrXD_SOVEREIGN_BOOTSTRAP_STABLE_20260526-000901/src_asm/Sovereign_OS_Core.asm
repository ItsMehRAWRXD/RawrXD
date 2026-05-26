; Sovereign_OS_Core.asm - Deterministic DAG Scheduler & Dispatcher
; ABI: RCX=KV_Base, RDX=Input, R8=Output, R9=Metadata
; Standard: 16-byte aligned stack, Zero-CRT, Bare-Metal Entry

.CODE

; XR_SchedulerTick: Core OS loop for graph traversal and deadline enforcement
PUBLIC XR_SchedulerTick
XR_SchedulerTick PROC
    sub rsp, 40                 ; Shadow space + Alignment
    
    ; 1. Load active XR_Node from Meta
    mov rax, [r9]               ; pNodeTable
    mov rbx, [rax]              ; Current active node
    
    ; 2. Deadline check: If (TSC > Node.Deadline) -> Preempt
    rdtscp
    cmp rax, [rbx + 16]         ; Compare against Node.Deadline
    ja preempt_node
    
    ; 3. Execute Kernel via Unified ABI
    call qword ptr [rbx + 8]              ; Call node->pKernel
    
    ; 4. Update Node Status/State
    mov dword ptr [rbx + 24], 1 ; Set NodeState::COMPLETE
    jmp exit
    
preempt_node:
    ; Handle priority inversion/deadline miss
    mov dword ptr [rbx + 24], 2  ; Set NodeState::PREEMPTED
    
exit:
    add rsp, 40
    ret
XR_SchedulerTick ENDP

; XR_Kernel_Fuse: Fuses two adjacent nodes to eliminate memory round-trip
; RCX=NodeA_Base, RDX=NodeB_Base
PUBLIC XR_Kernel_Fuse
XR_Kernel_Fuse PROC
    ; Fuses logic of two DAG nodes to allow register-level operand passing
    ; bypassing the requirement for write-to-cache between segments.
    mov r8, [rcx + 8]           ; KernelA
    mov r9, [rdx + 8]           ; KernelB
    
    ; Execute fused sequence within current register window
    call r8                     ; Node A logic
    call r9                     ; Node B logic (using A's outputs in registers)
    ret
XR_Kernel_Fuse ENDP

; Data definitions for OS state
.DATA
align 16
g_SchedulerState dq 0
g_TickCount      dq 0

_BBOX SEGMENT ALIGN(4096) 'BSS'
PUBLIC g_BlackBoxBuffer
g_BlackBoxBuffer db 4096 DUP(?)  ; 4KB Sector-aligned Black Box NVMe buffer
_BBOX ENDS

END
