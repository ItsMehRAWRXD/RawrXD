; ==============================================================================
; SOVEREIGN COHERENCE FENCE
; File: Sovereign_Coherence_Fence.asm
; Role: Deterministic Memory Visibility & Execution Safety Barrier
; BEACONISM: Enforces hardware-visible state transitions
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

.DATA
    g_CoherenceState QWORD 0

; STATE FLAGS
COHERENCE_INGEST   EQU 0
COHERENCE_COMMIT   EQU 1
COHERENCE_EXECUTE  EQU 2

.CODE

PUBLIC Sovereign_Coherence_BeginIngest
Sovereign_Coherence_BeginIngest PROC
    mov qword ptr [g_CoherenceState], COHERENCE_INGEST
    ret
Sovereign_Coherence_BeginIngest ENDP


PUBLIC Sovereign_Coherence_Commit
Sovereign_Coherence_Commit PROC
    ; Full memory visibility barrier
    mfence
    lfence

    mov qword ptr [g_CoherenceState], COHERENCE_COMMIT
    ret
Sovereign_Coherence_Commit ENDP


PUBLIC Sovereign_Coherence_EnterExecution
Sovereign_Coherence_EnterExecution PROC
    mfence
    lfence

    mov qword ptr [g_CoherenceState], COHERENCE_EXECUTE
    ret
Sovereign_Coherence_EnterExecution ENDP


PUBLIC Sovereign_Coherence_Check
Sovereign_Coherence_Check PROC
    mov rax, [g_CoherenceState]
    ret
Sovereign_Coherence_Check ENDP

END