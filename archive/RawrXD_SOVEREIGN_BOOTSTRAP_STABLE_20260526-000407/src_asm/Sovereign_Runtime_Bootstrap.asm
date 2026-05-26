; Sovereign_Runtime_Bootstrap.asm - Final Dispatch Initialization
; ABI: Entry point for the Sovereign OS Execution Monolith
; Purpose: Hand-off from C++ Hydrator to MASM Execution Space

.CODE

EXTERN XR_Compiler_FusePass : PROC
EXTERN XR_Runtime_Run : PROC
EXTERN XR_SchedulerTick : PROC

; XR_Runtime_Bootstrap: Transition from C++ context to Sovereign Kernel
; RCX = ManifestPtr, RDX = NodeCount
PUBLIC XR_Runtime_Bootstrap
XR_Runtime_Bootstrap PROC
    sub rsp, 40                 ; Shadow space

    ; 1. Compiler Pass: Static Fusion Analysis
    ; Pre-calculates register-level operand passing to avoid memory-roundtrips
    call XR_Compiler_FusePass

    ; 2. Dispatch Initialization: Register Plan
    ; Pointing the scheduler to our linearized execution plan (g_ExecutionPlan)
    lea rax, g_ExecutionPlan    
    mov [g_SchedulerState], 1   ; OS_RUNNING

    ; 3. Deterministic Entry: TITAN_LOOP
    ; Jump to the scheduler entry point for the first DAG node
    call XR_Runtime_Run

    add rsp, 40
    ret
XR_Runtime_Bootstrap ENDP

; TITAN_LOOP: The continuous execution cycle for the sovereign graph
; This loop maintains register pressure and L1/L2 cache locality
PUBLIC TITAN_LOOP
TITAN_LOOP PROC
    lea rbx, g_ExecutionPlan    ; Base of the execution plan

    ; Synchronization Barrier: Complete all reads/writes before operating on Graph
    mfence
    lfence

cycle:
    mov rcx, [rbx]              ; Load current node (KV-Cache context)
    test rcx, rcx               ; Check for end of DAG
    jz shutdown

    ; Invocation of the preemptive scheduler tick
    call XR_SchedulerTick
    
    ; Logic to iterate through plan (O(1) pointer arithmetic)
    add rbx, 8                  ; Next node in DAG
    jmp cycle

shutdown:
    xor rcx, rcx
    mov [g_SchedulerState], rcx ; OS_IDLE
    ret
TITAN_LOOP ENDP

.DATA
EXTERN g_ExecutionPlan : QWORD
EXTERN g_SchedulerState : QWORD
END
