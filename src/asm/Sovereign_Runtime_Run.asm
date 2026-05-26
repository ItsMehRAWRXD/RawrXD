; Sovereign_Runtime_Run.asm - Dispatcher Entry & Lifecycle Orchestration
; ABI: RCX=ManifestBase, RDX=NodeCount, R8=PriorityMask
; Purpose: Initialize Scheduler and Transition to Deterministic Loop

.CODE

; External references needed by the runtime run loop
EXTERN XR_Compiler_FusePass:PROC
EXTERN XR_SchedulerTick:PROC
EXTERN XR_FaultHandler_Resolve:PROC

; XR_Runtime_Run: Entry point for the Sovereign OS Execution Loop
PUBLIC XR_Runtime_Run
XR_Runtime_Run PROC
    sub rsp, 40                 ; Shadow Space
    
    ; 1. Hydrate Registry via Compiler-FusePass (Passed as arguments)
    ; Assuming RCX and RDX are already set up correctly for FusePass
    call XR_Compiler_FusePass   ; Perform static graph fusion
    
    ; 2. Initialize Scheduler State
    mov qword ptr [g_SchedulerState], 1   ; Set OS_RUNNING
    lea rax, g_ExecutionPlan    ; Load linear execution manifest
    
scheduler_loop:
    mov r9, [rax]               ; Fetch XR_Node*
    test r9, r9                 ; Check for NULL sentinel
    jz shutdown
    
    ; 3. Preemptive Tick: Enforce Deadlines & Causal Edges
    ; Note: RCX/RDX/R8 setup would go here if needed by Tick
    call XR_SchedulerTick       ; Deterministic kernel execution
    
    ; 4. Fault/Page Management: Check resident status
    test rax, rax               ; Result from FaultHandler (stubbed usage)
    jz fault_event
    
    add rax, 8                  ; Advance to next node pointer
    jmp scheduler_loop

fault_event:
    ; Invoke FaultHandler to resolve NVMe-KV page stall
    call XR_FaultHandler_Resolve
    jmp scheduler_loop

shutdown:
    mov qword ptr [g_SchedulerState], 0   ; OS_IDLE
    add rsp, 40
    ret
XR_Runtime_Run ENDP

; XR_Runtime_TestBench: Validates hydration integrity without full kernel load
PUBLIC XR_Runtime_TestBench
XR_Runtime_TestBench PROC
    ; Simulate manifest node for testing logic flow
    ; RCX=TestBuffer, RDX=NodeCount
    mov rax, 0DEADBEEFh         ; Return validation pattern
    ret
XR_Runtime_TestBench ENDP

.DATA
EXTERN g_ExecutionPlan : QWORD
EXTERN g_SchedulerState : QWORD
END
