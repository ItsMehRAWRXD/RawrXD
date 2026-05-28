; ==================================================================================
; SOVEREIGN RUNTIME ORCHESTRATOR
; File: Sovereign_Runtime_Orchestrator.asm
; Role: Governance of Execution State and Module Dispatch
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN Sovereign_Loader_Parse:PROC
EXTERN Sovereign_Topology_BindThread:PROC
EXTERN Sovereign_Warmup_Core:PROC
EXTERN Sovereign_DAG_Execute:PROC

.DATA
    g_RuntimeMappedFile QWORD 0
    g_RuntimeNodeId     QWORD 0

.CODE

PUBLIC Sovereign_Runtime_Init
Sovereign_Runtime_Init PROC
    ENTER_FRAME
    
    ; Preserve state
    mov [g_RuntimeMappedFile], rcx
    mov [g_RuntimeNodeId], rdx

    ; Bind Topology
    mov rcx, rdx
    call Sovereign_Topology_BindThread

    ; Load Registry
    mov rcx, [g_RuntimeMappedFile]
    call Sovereign_Loader_Parse
    test rax, rax
    jz @@Fail

    call Sovereign_Warmup_Core
    
    mov rax, 1
    EXIT_FRAME
    ret
@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Runtime_Init ENDP

; ==================================================================================
; Sovereign_Runtime_Dispatch
; RCX = Tensor Hash, RDX = Buffer Pointer
; ==================================================================================
PUBLIC Sovereign_Runtime_Dispatch
Sovereign_Runtime_Dispatch PROC
    ENTER_FRAME

    ; Orchestrate the Staging and Execution flow via the new flattened DAG Executor
    ; rather than single-tensor scheduling, but retain wrapper format if needed.
    
    ; Call DAG execution pipeline
    call Sovereign_DAG_Execute

    EXIT_FRAME
    ret
Sovereign_Runtime_Dispatch ENDP

END
