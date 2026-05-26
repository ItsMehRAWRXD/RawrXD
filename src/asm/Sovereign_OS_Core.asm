; Sovereign_OS_Core.asm - Deterministic DAG Scheduler & Dispatcher
; ABI: RCX=KV_Base, RDX=Input, R8=Output, R9=Metadata
; Standard: 16-byte aligned stack, Zero-CRT, Bare-Metal Entry

include Sovereign_Common.inc

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

; -----------------------------------------------------------------------------------------
; XR_Runtime_Tick (The Supervisor)
; Coordinates between Compiler, Linker, Executor, and Sync subsystems
; -----------------------------------------------------------------------------------------
PUBLIC XR_Runtime_Tick
XR_Runtime_Tick PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 32

    ; [1] Atomic Tick Increment
    lock inc qword ptr [g_ExecutionTick]
    
    ; [2] Network/Consensus Sync: Pull from Telemetry Ring
    ; This allows remote nodes to influence the local JIT priority
    call    XR_Registry_Pop_Telemetry
    cmp     rax, -1
    je      _NoNetworkUpdate
    ; Update local residency or weights based on Consensus Signal
    ; ...
_NoNetworkUpdate:

    ; [3] JIT Supervisor: Emission & Promotion Cycle
    ; Check if current instruction stream needs JIT synthesis
    lea     rcx, g_JIT_StagingArea
    mov     edx, 1                      ; OpType: MATMUL_HOT
    call    XR_JIT_Emit_Kernel
    mov     rbx, rax                    ; Save size of emitted code

    ; Inject Telemetry Probe immediately following the emitted kernel
    lea     rcx, g_JIT_StagingArea
    add     rcx, rbx
    mov     edx, 1                      ; Probe Type: 1 = TSC
    call    XR_JIT_Inject_Probe
    add     rbx, rax

    ; Push Event to Ring Buffer indicating JIT Tick Complete
    mov     rcx, rbx                    ; Value = Bytes JIT'd
    call    XR_Registry_Push_Telemetry
    
    ; [4] W^X Protection Transition & I-Cache Flush
    ; Converts RW staging area to EXECUTE_READ and invalidates CPU cache
    lea     rcx, g_JIT_StagingArea
    mov     rdx, rbx                    ; Size
    call    XR_Promote_To_Executable    ; (MemoryGuard)

    ; [5] Execution Dispatch (The Executor)
    ; Load active Residency Mask and scan for work
    mov     rsi, [g_ResidencyMask]
    test    rsi, rsi
    jz      _TickExit

_ProcessSegments:
    ; [3] Hardware Bit-Scan (Deterministic O(1) Scheduling)
    bsf     rax, rsi                    ; Find lowest set bit
    jz      _TickExit                   ; Branch if no more bits in segment
    
    ; rax = NodeIndex
    mov     rbx, rax                    ; Save index
    btr     rsi, rax                    ; Clear bit in local copy
    
    ; [4] Node Dispatch (V-Table/ABI compliant)
    ; In a production system, we lookup g_ExecNodes[rbx]
    ; lea rcx, g_ExecNodes
    ; shl rbx, 5
    ; call [rcx + rbx + ... Dispatcher ...]

    ; [5] Cyclic Transition: Check if node is done for this epoch
    ; Placeholder: Just simulated work
    pause
    
    jmp     _ProcessSegments

_NoWork:
    ; Potential sleep or wait for IO
    nop

_TickExit:
    add     rsp, 32
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
XR_Runtime_Tick ENDP

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
EXTERN XR_JIT_Emit_Kernel : PROC
EXTERN XR_JIT_Inject_Probe : PROC
EXTERN XR_Promote_To_Executable : PROC
EXTERN XR_Registry_Pop_Telemetry : PROC
EXTERN XR_Registry_Push_Telemetry : PROC
EXTERN g_SchedulerState : BYTE
EXTERN g_ExecutionTick : QWORD

; Import Global Registry (Kernel of Kernels Hub)
EXTERN g_SovereignRegistry : BYTE

; --- Telemetry Sink (Feedback Loop Context) ---
XR_TELEMETRY_CONTEXT STRUCT
    ExecCount       dq 0
    TotalCycles     dq 0
    LastStamp       dq 0
    Reserved        dq 0
XR_TELEMETRY_CONTEXT ENDS

align 16
g_TelemetryContext  XR_TELEMETRY_CONTEXT <>

align 16
g_TickCount      dq 0

_BBOX SEGMENT ALIGN(4096) 'BSS'
PUBLIC g_BlackBoxBuffer
g_BlackBoxBuffer db 4096 DUP(?)  ; 4KB Sector-aligned Black Box NVMe buffer
_BBOX ENDS

END
