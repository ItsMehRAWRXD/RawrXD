; AgentTelemetry.asm — MASM x64 telemetry for arena allocation tracking
; Non-blocking atomic counters for stress test monitoring
; Build: ml64 /c /Fo AgentTelemetry.obj AgentTelemetry.asm

; ============================================================================
; EXPORTS
; ============================================================================
PUBLIC AgentTelemetry_RecordAllocation
PUBLIC AgentTelemetry_RecordFree
PUBLIC AgentTelemetry_GetArenaUsed
PUBLIC AgentTelemetry_Reset

; ============================================================================
; DATA SECTION — Cache-aligned telemetry structure
; ============================================================================
.DATA

; 64-byte aligned telemetry block (fits in one cache line)
ALIGN 16
g_AgentTelemetry STRUCT
    arenaUsedBytes      DQ 0    ; +0   Total arena bytes allocated
    vramUsedBytes       DQ 0    ; +8   GPU memory (if applicable)
    proposalsGenerated  DD 0    ; +16
    proposalsApplied    DD 0    ; +20
    totalSwarmLatencyUs DQ 0    ; +24  Cumulative microseconds
    loopCount           DD 0    ; +32
    stateChecksum       DQ 0    ; +40  XXH64 of agent state
    ; Padding to 64 bytes
    _pad                DQ 0, 0, 0
    _pad2               DD 0
g_AgentTelemetry ENDS

; Global instance
ALIGN 16
g_telemetry g_AgentTelemetry <>

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordAllocation
; 
; Parameters:
;   RCX = size (bytes) to record
; 
; Returns:
;   None
; 
; Notes:
;   Uses lock xadd for atomic increment. Minimal overhead.
; ----------------------------------------------------------------------------
AgentTelemetry_RecordAllocation PROC FRAME
    .endprolog
    
    ; Atomically add size to arenaUsedBytes
    lock xadd qword ptr [g_telemetry.arenaUsedBytes], rcx
    
    ret
AgentTelemetry_RecordAllocation ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordFree
; 
; Parameters:
;   RCX = size (bytes) to subtract
; 
; Notes:
;   Negates size and atomically subtracts. Tracks net usage.
; ----------------------------------------------------------------------------
AgentTelemetry_RecordFree PROC FRAME
    .endprolog
    
    ; Negate size for subtraction
    neg rcx
    
    ; Atomically add (which subtracts)
    lock xadd qword ptr [g_telemetry.arenaUsedBytes], rcx
    
    ret
AgentTelemetry_RecordFree ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_GetArenaUsed
; 
; Returns:
;   RAX = current arena bytes used
; ----------------------------------------------------------------------------
AgentTelemetry_GetArenaUsed PROC FRAME
    .endprolog
    
    mov rax, qword ptr [g_telemetry.arenaUsedBytes]
    
    ret
AgentTelemetry_GetArenaUsed ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_Reset
; 
; Clears all telemetry counters (for checkpointing)
; ----------------------------------------------------------------------------
AgentTelemetry_Reset PROC FRAME
    .endprolog
    
    push rdi
    
    ; Zero the entire structure
    lea rdi, g_telemetry
    xor eax, eax
    mov ecx, SIZEOF g_AgentTelemetry / 8  ; QWORDs to clear
    rep stosq
    
    pop rdi
    ret
AgentTelemetry_Reset ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordProposalGenerated
; 
; Atomically increments proposalsGenerated counter
; ----------------------------------------------------------------------------
AgentTelemetry_RecordProposalGenerated PROC FRAME
    .endprolog
    
    lock inc dword ptr [g_telemetry.proposalsGenerated]
    
    ret
AgentTelemetry_RecordProposalGenerated ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordProposalApplied
; 
; Atomically increments proposalsApplied counter
; ----------------------------------------------------------------------------
AgentTelemetry_RecordProposalApplied PROC FRAME
    .endprolog
    
    lock inc dword ptr [g_telemetry.proposalsApplied]
    
    ret
AgentTelemetry_RecordProposalApplied ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordLoopIteration
; 
; Atomically increments loopCount
; ----------------------------------------------------------------------------
AgentTelemetry_RecordLoopIteration PROC FRAME
    .endprolog
    
    lock inc dword ptr [g_telemetry.loopCount]
    
    ret
AgentTelemetry_RecordLoopIteration ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_RecordSwarmLatency
; 
; Parameters:
;   RCX = latency in microseconds
; 
; Adds to cumulative swarm latency
; ----------------------------------------------------------------------------
AgentTelemetry_RecordSwarmLatency PROC FRAME
    .endprolog
    
    lock xadd qword ptr [g_telemetry.totalSwarmLatencyUs], rcx
    
    ret
AgentTelemetry_RecordSwarmLatency ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_UpdateStateChecksum
; 
; Parameters:
;   RCX = new XXH64 checksum value
; 
; Updates the state fidelity checksum
; ----------------------------------------------------------------------------
AgentTelemetry_UpdateStateChecksum PROC FRAME
    .endprolog
    
    mov qword ptr [g_telemetry.stateChecksum], rcx
    
    ret
AgentTelemetry_UpdateStateChecksum ENDP

; ----------------------------------------------------------------------------
; AgentTelemetry_DumpToBuffer
; 
; Parameters:
;   RCX = pointer to output buffer (min 128 bytes)
; 
; Formats telemetry as JSON-like string for logging
; ----------------------------------------------------------------------------
AgentTelemetry_DumpToBuffer PROC FRAME
    LOCAL outBuf:DQ
    
    .endprolog
    
    mov outBuf, rcx
    
    ; Simple sprintf-style formatting would go here
    ; For now, just copy raw values
    mov rax, qword ptr [g_telemetry.arenaUsedBytes]
    mov [rcx], rax
    mov rax, qword ptr [g_telemetry.vramUsedBytes]
    mov [rcx+8], rax
    mov eax, dword ptr [g_telemetry.proposalsGenerated]
    mov [rcx+16], eax
    mov eax, dword ptr [g_telemetry.proposalsApplied]
    mov [rcx+20], eax
    mov rax, qword ptr [g_telemetry.totalSwarmLatencyUs]
    mov [rcx+24], rax
    mov eax, dword ptr [g_telemetry.loopCount]
    mov [rcx+32], eax
    mov rax, qword ptr [g_telemetry.stateChecksum]
    mov [rcx+40], rax
    
    ret
AgentTelemetry_DumpToBuffer ENDP

END
