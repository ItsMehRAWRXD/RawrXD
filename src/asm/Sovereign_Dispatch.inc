; ==================================================================================
; SOVEREIGN SIMD LANE-DISPATCH ORCHESTRATOR HEADER
; Phase 2C - Dispatch Engine Include
; ==================================================================================

; Define Work Opcodes
OPCODE_F32_DOT     EQU 0
OPCODE_Q4_K_DOT    EQU 1

; Tightly packed work item for the dispatcher
SOVEREIGN_WORK_ITEM STRUCT 16
    Opcode          DQ 0    ; Opcode routing key
    pWeights        DQ 0    ; ALIGNED 64 pointer to weights
    pActivations    DQ 0    ; ALIGNED 64 pointer to activation state
    pOutput         DQ 0    ; Output buffer destination
    NumElements     DQ 0    ; Total elements to process
    Stride          DQ 0    ; Stride length for advanced topology
SOVEREIGN_WORK_ITEM ENDS

EXTERNDEF Sovereign_Dispatch_Queue:PROC
