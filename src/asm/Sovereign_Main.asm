; ==============================================================================
; Sovereign_Main.asm
; Zero-Dependency Bare-Metal Entry Point (TITAN_LOOP Kernel)
; ==============================================================================

include Sovereign_Common.inc

; --- External Symbols ---
EXTERN Sovereign_Init_Registry        : PROC
EXTERN Sovereign_Registry_Step_Lean   : PROC
EXTERN Sovereign_Watchdog_Reset_Loop  : PROC
EXTERN Sovereign_Check_Stealth_State  : PROC

; --- Global Data ---
.DATA
    PUBLIC g_Active_ID
    PUBLIC g_LastCycleTSC
    PUBLIC g_SovereignHub
    
    g_Active_ID     dq 0
    g_LastCycleTSC  dq 0
    g_SovereignHub  dq 100 dup(0) ; Registry Placeholder

.CODE

PUBLIC Sovereign_Entry

; ------------------------------------------------------------------------------
; Sovereign_Entry
; Bare-metal entry point (C-Monolith style)
; ------------------------------------------------------------------------------
Sovereign_Entry PROC
    sub rsp, 40
    
    ; 1. Initialize Registry
    call Sovereign_Init_Registry
    
    ; 2. Enter Cyclic Dispatch (The Heart)
    call Sovereign_Kernel_MainLoop
    
    add rsp, 40
    ret
Sovereign_Entry ENDP

; ------------------------------------------------------------------------------
; Sovereign_Kernel_MainLoop (TITAN_LOOP)
; Fixed frequency, jitter-free execution core.
; ------------------------------------------------------------------------------
Sovereign_Kernel_MainLoop PROC
@@TitanLoop:
    ; 1. Integrity Shield: Verify Stealth & Jitter
    EXTERN Sovereign_Verify_Integrity : PROC
    call Sovereign_Verify_Integrity
    test rax, rax
    jnz @@SelfDestruct

    ; 2. Apex: Reset/Prepare Watchdog
    call Sovereign_Watchdog_Reset_Loop
    
    ; 3. Braid Execution: Step the Registry
    mov rcx, [g_Active_ID]
    lea rdx, [g_SovereignHub]
    call Sovereign_Registry_Step_Lean
    
    ; 4. System Heartbeat (TSC Telemetry)
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    mov r8, [g_LastCycleTSC]
    mov [g_LastCycleTSC], rax
    sub rax, r8              ; rax = Delta cycles
    
    jmp @@TitanLoop

@@SelfDestruct:
    ; 5. Detection Triggered: Silent Shutdown via Direct Syscall
    EXTERN Sovereign_Direct_Exit : PROC
    mov rcx, 0DEADBEEFh      ; Exit Code
    call Sovereign_Direct_Exit
    ret
Sovereign_Kernel_MainLoop ENDP

END