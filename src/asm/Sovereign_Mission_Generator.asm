; =========================================================================================
; FILE: Sovereign_Mission_Generator.asm
; SUBSYSTEM: PROCEDURAL MISSION & STORY LOGIC
; Pure x64 MASM / No Dependencies / Lock-Free
; Purpose: Generates deterministic missions (Story, Side-quests, Dynamic Events) with 
;          linear/non-linear branching and trigger-based objective tracking.
; =========================================================================================

.DATA
; PRNG for Mission seeds
align 8
g_Mission_PRNG_State dq 0AABBCCDD11223344h

.CODE

; -----------------------------------------------------------------------------------------
; MISSION ARCHITECTURE CONSTANTS
; -----------------------------------------------------------------------------------------
; Mission Categories
MISSION_STORY       EQU 1
MISSION_SIDE_QUEST  EQU 2
MISSION_DYNAMIC     EQU 3

; Structure Types
STRUCT_LINEAR       EQU 1
STRUCT_BRANCHING    EQU 2
STRUCT_OPEN_WORLD   EQU 3

; Objective Types
OBJ_REACH_POI       EQU 1
OBJ_ELIMINATE       EQU 2
OBJ_RETRIEVE        EQU 3
OBJ_PROTECT         EQU 4
OBJ_INTERACT        EQU 5

; Trigger Conditions
TRIG_PROXIMITY      EQU 1
TRIG_TIMER          EQU 2
TRIG_EVENT_FLAG     EQU 3

; -----------------------------------------------------------------------------------------
; MISSION_NODE Structure (16 bytes)
; [0-3]   ObjectiveType
; [4-7]   TargetPOI_ID
; [8-11]  TriggerType
; [12-15] NextNode_ID (for Linear) or BranchID (for Non-linear)
; -----------------------------------------------------------------------------------------

; -----------------------------------------------------------------------------------------
; UINT64 Fast_Rand_Mission()
; -----------------------------------------------------------------------------------------
Fast_Rand_Mission PROC
    mov rax, qword ptr [g_Mission_PRNG_State]
    mov rdx, rax
    shl rdx, 12
    xor rax, rdx
    mov rdx, rax
    shr rdx, 25
    xor rax, rdx
    mov rdx, rax
    shl rdx, 27
    xor rax, rdx
    mov qword ptr [g_Mission_PRNG_State], rax
    mov rdx, 2685821657736338717
    imul rax, rdx
    ret
Fast_Rand_Mission ENDP

; -----------------------------------------------------------------------------------------
; UINT32 Sovereign_Generate_Mission(void* pNodeBuffer, UINT32 category, UINT32 complexity)
; RCX = pNodeBuffer
; RDX = category (Story/Side/Dynamic)
; R8  = complexity (Number of objectives/steps)
; Returns Number of steps generated in RAX.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Generate_Mission
Sovereign_Generate_Mission PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    test rcx, rcx
    jz @@Error
    test r8, r8
    jz @@Error

    mov rdi, rcx                   ; rdi = buffer
    mov rsi, r8                    ; rsi = steps remaining
    xor rbx, rbx                   ; count

@@GenLoop:
    test rsi, rsi
    jz @@Done

    ; 1) Objective Type (1-5)
    call Fast_Rand_Mission
    xor rdx, rdx
    mov r9, 5
    div r9
    inc rdx                        ; rdx = OBJ_ID
    mov dword ptr [rdi], edx

    ; 2) Target POI (1-11 randomly from World map POIs)
    call Fast_Rand_Mission
    xor rdx, rdx
    mov r9, 11
    div r9
    inc rdx
    mov dword ptr [rdi+4], edx

    ; 3) Trigger Type (1-3)
    call Fast_Rand_Mission
    xor rdx, rdx
    mov r9, 3
    div r9
    inc rdx
    mov dword ptr [rdi+8], edx

    ; 4) Structure logic: Link to next step or branch
    dec rsi
    mov eax, ebx
    inc eax                        ; Target next element index
    test rsi, rsi
    jnz @@SetNext
    mov eax, 0FFFFFFFFh            ; End of mission flag
@@SetNext:
    mov dword ptr [rdi+12], eax

    add rdi, 16                    ; Next node
    inc rbx
    jmp @@GenLoop

@@Done:
    mov rax, rbx
    jmp @@Exit
@@Error:
    xor rax, rax
@@Exit:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Generate_Mission ENDP

; -----------------------------------------------------------------------------------------
; UINT32 Sovereign_Mission_CheckTrigger(UINT32 currentTriggerType, double currentVal, double targetThreshold)
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Mission_CheckTrigger
Sovereign_Mission_CheckTrigger PROC
    ; RCX = Type, XMM0 = currentVal, XMM1 = targetThreshold
    xor rax, rax
    
    cmp ecx, TRIG_PROXIMITY
    je @@ProxCheck
    cmp ecx, TRIG_TIMER
    je @@TimeCheck
    jmp @@NoMatch

@@ProxCheck:
    ; Proximity: Done if currentVal <= targetThreshold
    comisd xmm1, xmm0              ; compare target vs current
    jae @@Triggered
    ret

@@TimeCheck:
    ; Timer: Done if currentVal >= targetThreshold
    comisd xmm0, xmm1
    jae @@Triggered
    ret

@@Triggered:
    mov rax, 1
@@NoMatch:
    ret
Sovereign_Mission_CheckTrigger ENDP

END