; Sovereign_Execution_Graph_ABI.inc - Register Pining & ABI Constants
; Pure x64 MASM / No Dependencies
; Purpose: Defines static register pins and constants for the Sovereign OS Graph ABI.

; -----------------------------------------------------------------------------------------
; DAG EXECUTOR PINNED REGISTERS (HOT PATH)
; -----------------------------------------------------------------------------------------
; R12-R15 remain completely pinned during the "hot path" of subgraph execution.
VM_CONTEXT_PTR      EQU r12  ; Pointer to the current Execution Graph Node
DAG_MATRIX_BASE     EQU r13  ; Pointer to the active tensor map (Ring Bridge Aperture)
SCRATCH_PAD_PTR     EQU r14  ; Fast access array for thread-local temporal allocations
WELFORD_GOV_STATE   EQU r15  ; Telemetry Base for 3-Sigma Governor evaluation

; -----------------------------------------------------------------------------------------
; SIMD EXECUTION PINNED REGISTERS
; -----------------------------------------------------------------------------------------
; XMM12: High-speed Accumulator State
; XMM13: Immediate Broadcast Scalar
; XMM14: Activation Threshold Bounds 
; XMM15: Entropy Delta State

; -----------------------------------------------------------------------------------------
; EXTERNAL LOGIC PROTOS
; -----------------------------------------------------------------------------------------
EXTERN XR_Registry_RegisterNode : PROC
EXTERN XR_Compiler_FusePass : PROC
EXTERN XR_Dependency_Validate : PROC
EXTERN Sovereign_Initialize_All_Systems : PROC
EXTERN Sovereign_Update_Gameplay_Tick : PROC

; -----------------------------------------------------------------------------------------
; ABI MACROS
; -----------------------------------------------------------------------------------------
ABI_PUSH_FRAME MACRO
    push rbp
    mov rbp, rsp
    sub rsp, 48
ENDM

ABI_POP_FRAME MACRO
    add rsp, 48
    pop rbp
ENDM

; -----------------------------------------------------------------------------------------
; DATA REFERENCES
; -----------------------------------------------------------------------------------------
EXTERNDEF g_NodeRegistryTable : BYTE
EXTERNDEF g_GraphStatus       : QWORD
EXTERNDEF g_ExecutionPlan     : BYTE
EXTERNDEF g_SchedulerState    : BYTE
EXTERNDEF g_ExecutionTick     : QWORD
