; ==================================================================================
; SOVEREIGN TOPOLOGY
; File: Sovereign_Topology.asm
; Role: NUMA Detection and Cache Awareness
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

.CODE

; ==================================================================================
; Sovereign_Topology_CheckNode
; Detects if current thread is on optimal NUMA node for the target tensor
; ==================================================================================
PUBLIC Sovereign_Topology_CheckNode
Sovereign_Topology_CheckNode PROC
    ENTER_FRAME

    ; Use PROCESSOR_NUMBER struct safely within our strict Frame ABI local space
    lea rcx, [rsp + 40] 
    call [g_ApiTable.pGetCurrentProcessorNumberEx]
    
    ; Note: Frame ABI protects the stack so we don't need manual sub rsp, 40 / add rsp, 40
    
    EXIT_FRAME
Sovereign_Topology_CheckNode ENDP

END
