; ==============================================================================
; Sovereign_Gameplay_Bridge.asm
; Logic: Global Dispatcher for All Subsystems
; ==============================================================================

include Sovereign_Common.inc

; ------------------------------------------------------------------------------
; EXTERNAL REFERNECE TO SUBSYSTEMS
; ------------------------------------------------------------------------------
EXTERN InitializeWantedSystem   : PROC
EXTERN UpdateWantedSystem       : PROC
EXTERN InitializeWorldNetwork     : PROC
EXTERN InitializeGeoMapper        : PROC
EXTERN InitializeEntropyEngine    : PROC
EXTERN InitializeVehiclePhysics   : PROC
EXTERN UpdateVehiclePhysics       : PROC
EXTERN UpdateBallistics           : PROC
EXTERN RenderHudOverlay           : PROC
EXTERN LoadGameState              : PROC

PUBLIC Sovereign_Initialize_All_Systems
PUBLIC Sovereign_Update_Gameplay_Tick

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Initialize_All_Systems
; Called during engine bootstrap to init all registered modules.
; ------------------------------------------------------------------------------
Sovereign_Initialize_All_Systems PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32

    ; Entropy/RNG
    call InitializeEntropyEngine
    
    ; World & Maps
    call InitializeWorldNetwork
    call InitializeGeoMapper
    
    ; Game Systems
    call InitializeWantedSystem
    call InitializeVehiclePhysics
    
    ; Persistence (Auto-Load)
    ; call LoadGameState ; Optional

    add rsp, 32
    pop rbp
    ret
Sovereign_Initialize_All_Systems ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Update_Gameplay_Tick
; Called once per cyclic heartbeat frame.
; RCX = DeltaTime (XMM0 usually)
; ------------------------------------------------------------------------------
Sovereign_Update_Gameplay_Tick PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Physics/Sim
    ; (XMM0 assumed to be DeltaTime)
    call UpdateVehiclePhysics
    call UpdateBallistics
    
    ; Logic
    call UpdateWantedSystem
    
    ; Rendering (Overlay)
    call RenderHudOverlay

    add rsp, 32
    pop rbp
    ret
Sovereign_Update_Gameplay_Tick ENDP

END