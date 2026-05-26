; ==============================================================================
; Sovereign_Input_Hub.asm
; Logic: Tactical Combat & Stealth Input Processor
; Features: Prone, Zip-Tie, Human Shield, Quick-Swap
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

; ------------------------------------------------------------------------------
; ACTION CODES
; ------------------------------------------------------------------------------
ACT_IDLE        EQU 0
ACT_WALK        EQU 1
ACT_PRONE       EQU 2
ACT_ZIP_TIE     EQU 3
ACT_SHIELD      EQU 4

.DATA
    align 8
    g_PlayerAction      dq ACT_IDLE
    g_TargetEntityID    dq -1
    g_StealthMultiplier dq 1 ; X1.0 scale

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: ProcessTacticalInput
; Input: RCX = InputBitmask
; Logic: Interprets raw HID states into game-generator actions.
; ------------------------------------------------------------------------------
PUBLIC ProcessTacticalInput
ProcessTacticalInput PROC
    ; Bit 0: Walk
    ; Bit 1: Prone
    ; Bit 2: Contextual (Zip/Shield)
    
    test rcx, 2     ; Prone check
    jnz L_DoProne
    
    test rcx, 4     ; Context check
    jnz L_DoContext
    
    mov qword ptr [g_PlayerAction], ACT_WALK
    jmp L_Done

L_DoProne:
    mov qword ptr [g_PlayerAction], ACT_PRONE
    mov qword ptr [g_StealthMultiplier], 2 ; 2x Stealth bonus
    jmp L_Done

L_DoContext:
    ; Check proximity to nearest AI entity
    ; If AI.Health < 20% -> Zip-Tie
    ; If AI.Health > 80% and Held -> Human Shield
    mov qword ptr [g_PlayerAction], ACT_ZIP_TIE ; Default zip
    
L_Done:
    ret
ProcessTacticalInput ENDP

END