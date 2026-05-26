; ==============================================================================
; Sovereign_Feature_Manifest.asm
; Master Index for all High-Performance Open-World Reverse-Engineered Features
; Purpose: Linkage and indexing for the Sovereign "Builder's Plug"
; ==============================================================================

; ------------------------------------------------------------------------------
; CORE MODULES
; ------------------------------------------------------------------------------
EXTERN InitializeWorldNetwork : PROC
EXTERN GenerateWorldTopology  : PROC
EXTERN InitializePlayerSessions : PROC
EXTERN HandleNetworkTick      : PROC

; ------------------------------------------------------------------------------
; PROTAGONIST & INPUT
; ------------------------------------------------------------------------------
EXTERN SwitchProtagonist      : PROC
EXTERN GetActiveProtagInfo     : PROC
EXTERN ProcessTacticalInput    : PROC

; ------------------------------------------------------------------------------
; MISSIONS & DIALOGUE
; ------------------------------------------------------------------------------
EXTERN TriggerMissionStep     : PROC
EXTERN GetNPCResponse         : PROC

; ------------------------------------------------------------------------------
; WORLD SYSTEMS
; ------------------------------------------------------------------------------
EXTERN CommitCrime            : PROC
EXTERN UpdateWantedSystem      : PROC
EXTERN AssignRPRole           : PROC
EXTERN ProcessMapTile         : PROC

; ------------------------------------------------------------------------------
; VEHICLES & BALLISTICS (NEW)
; ------------------------------------------------------------------------------
EXTERN UpdateVehiclePhysics   : PROC
EXTERN FireProjectile         : PROC
EXTERN UpdateProjectiles      : PROC

; ------------------------------------------------------------------------------
; UI & PERSISTENCE (NEW)
; ------------------------------------------------------------------------------
EXTERN RenderHudOverlay       : PROC
EXTERN SaveGameState          : PROC
EXTERN LoadGameState          : PROC

; ------------------------------------------------------------------------------
; BOOTSTRAP & KERNEL (NEW)
; ------------------------------------------------------------------------------
EXTERN Sovereign_Engine_Bootstrap : PROC
EXTERN Sovereign_Kernel_MainLoop  : PROC
EXTERN Sovereign_Pulse_L2         : PROC

; ------------------------------------------------------------------------------
; MEDIA & COMMS
; ------------------------------------------------------------------------------
EXTERN PlayMediaStream        : PROC
EXTERN SendPhoneMessage       : PROC

.DATA
    align 8
    ; Feature Dispatch Table (FDT) for the "Builder's Tool"
    g_FeatureTable dq InitializeWorldNetwork
                   dq GenerateWorldTopology
                   dq InitializePlayerSessions
                   dq HandleNetworkTick
                   dq SwitchProtagonist
                   dq GetActiveProtagInfo
                   dq ProcessTacticalInput
                   dq TriggerMissionStep
                   dq GetNPCResponse
                   dq CommitCrime
                   dq UpdateWantedSystem
                   dq AssignRPRole
                   dq ProcessMapTile
                   dq PlayMediaStream
                   dq SendPhoneMessage
                   dq UpdateVehiclePhysics
                   dq FireProjectile
                   dq UpdateProjectiles
                   dq RenderHudOverlay
                   dq SaveGameState
                   dq LoadGameState
                   dq Sovereign_Engine_Bootstrap
                   dq Sovereign_Kernel_MainLoop
                   dq Sovereign_Pulse_L2

    g_FeatureCount dq 24

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: GetFeatureById
; Input: RCX = Index
; Output: RAX = Function Pointer
; ------------------------------------------------------------------------------
PUBLIC GetFeatureById
GetFeatureById PROC
    cmp rcx, [g_FeatureCount]
    jae L_Error
    lea rax, [g_FeatureTable]
    mov rax, [rax + rcx*8]
    ret
L_Error:
    xor rax, rax
    ret
GetFeatureById ENDP

END