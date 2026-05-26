; ==============================================================================
; Sovereign_Protagonist_Switch.asm
; Logic: Dual Protagonist (Jason/Lucia) State-Swapping Engine
; Bypasses OS scheduler jitter; utilizes direct graph execution nodes.
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

; ------------------------------------------------------------------------------
; PROTAGONIST DEFINITIONS
; ------------------------------------------------------------------------------
PROTAG_JASON    EQU 0
PROTAG_LUCIA    EQU 1

; Protagonist State Structure (cache line sizing)
PROTAG_STATE STRUCT
    ActiveID        dq ?    ; 0 or 1
    CurrentHealth   dq ?
    CurrentArmor    dq ?
    LastPosX        dq ?
    LastPosY        dq ?
    LastPosZ        dq ?
    SpecialAbility  dq ?    ; Charge meter [0-100]
    Padding         dq ?    ; Align to 64 bytes
PROTAG_STATE ENDS

.DATA
    ALIGN 16
    g_ProtagStates  PROTAG_STATE 2 DUP(<?>)
    g_CurrentIndex  dq PROTAG_JASON
    g_PendingSwitch dq 0 ; Atomic switch flag

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Protagonist_Switch_Initialize
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Protagonist_Switch_Initialize
Sovereign_Protagonist_Switch_Initialize PROC
    mov qword ptr [g_CurrentIndex], PROTAG_JASON
    ; Init Jason
    lea rax, [g_ProtagStates]
    mov qword ptr [rax], PROTAG_JASON
    mov qword ptr [rax + 8], 100 ; Health
    ; Init Lucia
    lea rax, [g_ProtagStates + 64]
    mov qword ptr [rax], PROTAG_LUCIA
    mov qword ptr [rax + 8], 100 ; Health
    ret
Sovereign_Protagonist_Switch_Initialize ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Protagonist_Switch_Update
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Protagonist_Switch_Update
Sovereign_Protagonist_Switch_Update PROC
    ; Process ability recharge etc
    ret
Sovereign_Protagonist_Switch_Update ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: SwitchProtagonist
; Input: RCX = TargetID (0 or 1)
; Logic: Atomic swap of execution context. Triggered by DAG VM loop.
; ------------------------------------------------------------------------------
PUBLIC SwitchProtagonist
SwitchProtagonist PROC
    ; 1. Validate Target
    cmp rcx, 1
    ja L_Done
    
    ; 2. Check if switch is already target
    cmp rcx, [g_CurrentIndex]
    je L_Done
    
    ; 3. Perform Context Serialization (Save current)
    mov rax, [g_CurrentIndex]
    imul rax, SIZEOF PROTAG_STATE
    lea rdx, [g_ProtagStates + rax]
    
    ; Save spatial data (R12 = VM Context potentially has it)
    ; For now, assume state is updated by physics engine in real-time.
    
    ; 4. Atomic Transition
    lock xchg [g_CurrentIndex], rcx
    
    ; 5. Trigger Camera Transition Event (Kernel-Level)
    ; Notify Renderer/Audio to swap listener position.
    
L_Done:
    ret
SwitchProtagonist ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: GetActiveProtagInfo
; Output: RAX = Pointer to active PROTAG_STATE
; ------------------------------------------------------------------------------
PUBLIC GetActiveProtagInfo
GetActiveProtagInfo PROC
    mov rax, [g_CurrentIndex]
    imul rax, SIZEOF PROTAG_STATE
    lea rax, [g_ProtagStates + rax]
    ret
GetActiveProtagInfo ENDP

END