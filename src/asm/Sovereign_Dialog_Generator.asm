; =========================================================================================
; FILE: Sovereign_Dialog_Generator.asm
; SUBSYSTEM: PROCEDURAL DIALOG & RESPONSE SYSTEM
; Pure x64 MASM / No Dependencies / Lock-Free
; Purpose: Generates deterministic dialog trees and NPC responses based on personality,
;          faction alignment, and world state. Returns indexed dialog fragments.
; =========================================================================================

.DATA
; PRNG for Dialog seeds
align 8
g_Dialog_PRNG_State dq 0FEDCBA9876543210h

.CODE

; -----------------------------------------------------------------------------------------
; DIALOG ARCHITECTURE CONSTANTS
; -----------------------------------------------------------------------------------------
; Dialog Categories
DIALOG_GREETING     EQU 1
DIALOG_QUEST        EQU 2
DIALOG_TRADE        EQU 3
DIALOG_THREAT       EQU 4
DIALOG_IDLE         EQU 5

; Tones/Personalities
TONE_FRIENDLY       EQU 1
TONE_STERN          EQU 2
TONE_HOSTILE        EQU 3
TONE_PROFESSIONAL   EQU 4

; Response Types
RESP_POSITIVE       EQU 1
RESP_NEGATIVE       EQU 2
RESP_NEUTRAL        EQU 3
RESP_QUERY          EQU 4

; -----------------------------------------------------------------------------------------
; UINT64 Fast_Rand_Dialog()
; -----------------------------------------------------------------------------------------
Fast_Rand_Dialog PROC
    mov rax, qword ptr [g_Dialog_PRNG_State]
    mov rdx, rax
    shl rdx, 12
    xor rax, rdx
    mov rdx, rax
    shr rdx, 25
    xor rax, rdx
    mov rdx, rax
    shl rdx, 27
    xor rax, rdx
    mov qword ptr [g_Dialog_PRNG_State], rax
    mov rdx, 2685821657736338717
    imul rax, rdx
    ret
Fast_Rand_Dialog ENDP

; -----------------------------------------------------------------------------------------
; UINT64 Sovereign_Generate_Dialog(UINT32 category, UINT32 tone, UINT32 seedOverride)
; RCX = category (Greeting, Quest, etc.)
; RDX = tone (Friendly, Hostile, etc.)
; R8  = seedOverride (Optional, 0 to use global state)
; Returns packed Dialog Descriptor in RAX.
; Bit Layout:
; [0-7]   Category ID
; [8-15]  Tone ID
; [16-23] Selected Fragment Index (Base phrase)
; [24-31] Variation Modifier (Nuance)
; [32-63] Context Hash (For UI icon/animation triggers)
; -----------------------------------------------------------------------------------------
PUBLIC GetNPCResponse
GetNPCResponse PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog

    mov ebx, ecx                   ; ebx = category
    mov esi, edx                   ; esi = tone

    ; Apply seed override if provided
    test r8, r8
    jz @@InvokeRand
    mov qword ptr [g_Dialog_PRNG_State], r8

@@InvokeRand:
    ; 1) Generate Fragment Index (0-255 phrase pool)
    call Fast_Rand_Dialog
    mov r9, rax                    ; Save full random bits
    and r9, 0FFh                   ; Fragment Index
    
    ; 2) Generate Variation Modifier (0-255)
    call Fast_Rand_Dialog
    mov r10, rax
    and r10, 0FFh                  ; Nuance

    ; 3) Generate Context Hash
    call Fast_Rand_Dialog
    mov r11, rax
    shr r11, 32                    ; Use upper bits for Context Hash

    ; Build packed result
    xor rax, rax
    mov al, bl                     ; Byte 0: Category
    
    ; AH cannot be used with SIL in x64 (REX prefix limitation)
    movzx rdx, sil
    shl rdx, 8
    or rax, rdx                    ; Byte 1: Tone
    
    mov rdx, r9
    and rdx, 0FFh
    shl rdx, 16                     
    or rax, rdx                    ; Byte 2: Fragment Index
    
    mov rdx, r10
    and rdx, 0FFh
    shl rdx, 24
    or rax, rdx                    ; Byte 3: Variation
    
    shl r11, 32
    or rax, r11                    ; Upper 32: Context Hash

    pop rsi
    pop rbx
    ret
GetNPCResponse ENDP

; -----------------------------------------------------------------------------------------
; UINT32 Sovereign_Dialog_CheckReaction(UINT32 playerReputation, UINT32 factionID)
; RCX = playerReputation (0-100)
; RDX = factionID
; Returns Tone ID to use for Dialog generation.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Dialog_CheckReaction
Sovereign_Dialog_CheckReaction PROC
    ; Simple logic: High rep = Friendly, Low rep = Hostile
    cmp ecx, 20
    jb @@Hostile
    cmp ecx, 80
    ja @@Friendly
    
    ; Neutral / Professional range
    mov rax, TONE_PROFESSIONAL
    cmp edx, 5                     ; Suppose Faction 5 is "Strict Military"
    je @@Exit
    mov rax, TONE_STERN
    ret

@@Hostile:
    mov rax, TONE_HOSTILE
    ret
@@Friendly:
    mov rax, TONE_FRIENDLY
@@Exit:
    ret
Sovereign_Dialog_CheckReaction ENDP

END