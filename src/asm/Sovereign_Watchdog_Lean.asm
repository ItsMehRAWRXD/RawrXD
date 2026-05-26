; ==============================================================================
; Sovereign_Watchdog_Lean.asm - O(1) Performance Monitor
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

.DATA
EXTERN g_SovereignHub : SovereignHub

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Watchdog_Profile_Lean_V2
; Profile loop cycle delta, update peaks if breached.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Watchdog_Profile_Lean_V2
Sovereign_Watchdog_Profile_Lean_V2 PROC
    push r12
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax
    
    ; Execute Braid Logic (Internal)
    ; In a complex monolith, this would jump/call the current active task
    ; call Sovereign_Click2_Rebind ; (Placeholder for braid logic)
    
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r12
    
    ; Atomic-Free Comparison (Optimization)
    EXTERN Titan_Peak_Cycles : QWORD
    cmp rax, [Titan_Peak_Cycles]
    jle @@Exit
    mov [Titan_Peak_Cycles], rax
@@Exit:
    pop r12
    ret
Sovereign_Watchdog_Profile_Lean_V2 ENDP

; ----------------------------------------------------------------------------
; Sovereign_Watchdog_Reset_Loop
; Called at the apex of TITAN_LOOP.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Watchdog_Reset_Loop
Sovereign_Watchdog_Reset_Loop PROC
    ; Reset loop-specific telemetry if needed
    ret
Sovereign_Watchdog_Reset_Loop ENDP

END
