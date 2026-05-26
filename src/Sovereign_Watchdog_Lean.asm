; ==============================================================================
; Sovereign_Watchdog_Lean.asm
; Ultra-Lean Registry Watchdog - Zero EMA / Zero Allocation
; Pure x64 MASM / Zero Dependencies
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

.DATA?
    ALIGN 8
    PUBLIC Titan_Peak_Cycles
    PUBLIC Titan_Peak_ID
    Titan_Peak_Cycles dq ? ; The highest cycle count recorded in the current loop
    Titan_Peak_ID     dq ? ; The Hotpatch_ID that caused it

.CODE

EXTERN Sovereign_Click2_Rebind : PROC

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Watchdog_Reset_Loop
; Logic: Zero out the current peak tracker instantly at the apex of the loop.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Watchdog_Reset_Loop
Sovereign_Watchdog_Reset_Loop PROC
    xor rax, rax
    mov [Titan_Peak_Cycles], rax
    mov [Titan_Peak_ID], rax
    ret
Sovereign_Watchdog_Reset_Loop ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Watchdog_Profile_Lean
; Input:  RCX = Hotpatch_ID, RDX = Hub_Pointer (SOVEREIGN_HUB)
; Logic: High-speed inline profiler with RDTSC and Peak comparison.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Watchdog_Profile_Lean
Sovereign_Watchdog_Profile_Lean PROC
    push rbx
    push r12
    push rcx                  ; Save Hotpatch_ID
    push rdx                  ; Save Hub_Pointer

    ; 1. Start Timestamp
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax              ; R12 = Start Ticks

    ; 2. Execute Asset (Simulated for this profiler)
    ; In real usage, this would call the actual asset callback.
    call Sovereign_Click2_Rebind

    ; 3. End Timestamp
    rdtsc
    shl rdx, 32
    or rax, rdx               ; RAX = End Ticks
    
    ; 4. Calculate Delta
    sub rax, r12              ; RAX = Elapsed Cycles
    pop rdx                   ; Restore Hub_Pointer
    pop rcx                   ; Restore Hotpatch_ID

    ; 5. Update Hub Telemetry
    cmp rax, [rdx].SOVEREIGN_HUB.Peak_Cycles
    jle .Done
    mov [rdx].SOVEREIGN_HUB.Peak_Cycles, rax
    mov [rdx].SOVEREIGN_HUB.Peak_AssetID, rcx
    mov [rdx].SOVEREIGN_HUB.Peak_AssetType, ASSET_TYPE_PATCH

    ; Also update local trackers
    mov [Titan_Peak_Cycles], rax
    mov [Titan_Peak_ID], rcx

.Done:
    pop r12
    pop rbx
    ret
Sovereign_Watchdog_Profile_Lean ENDP

END
