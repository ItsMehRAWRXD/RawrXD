; =========================================================================================
; FILE: Sovereign_Phone_System.asm
; SUBSYSTEM: MULTIPLAYER VOICE/TEXT COMMS & DIRECTORY
; Pure x64 MASM / No Dependencies / Lock-Free
; Purpose: Manages persistent phone numbers, dialing, and call states for the 1024-player
;          network. Uses the 64-byte per player cache-aligned network structure.
; =========================================================================================

.DATA
; PRNG for Phone Number Generation (Unique 10-digit style)
align 8
g_Phone_PRNG_State dq 1122334455667788h

.CODE

; -----------------------------------------------------------------------------------------
; PLAYER PHONE STRUCTURE OFFSET (Within the 64-byte Network State)
; -----------------------------------------------------------------------------------------
OFF_PHONE_NUM       EQU 8    ; QWORD: Player's My Phone Number
OFF_CALL_TARGET     EQU 16   ; QWORD: Number currently dialing/connected to
OFF_CALL_STATUS     EQU 24   ; DWORD: 0=IDLE, 1=DIALING, 2=RINGING_IN, 3=CONNECTED
OFF_CALL_START_TSC  EQU 32   ; QWORD: TSC at start (for billing/duration)

; Status Constants
STATUS_IDLE         EQU 0
STATUS_DIALING      EQU 1
STATUS_RINGING      EQU 2
STATUS_CONNECTED    EQU 3

; -----------------------------------------------------------------------------------------
; UINT64 Sovereign_Phone_AssignNumber(void* pPlayerState)
; Generates a unique-ish 10-digit phone number and saves it to the player structure.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Phone_AssignNumber
Sovereign_Phone_AssignNumber PROC
    ; Simple XorShift roll
    mov rax, qword ptr [g_Phone_PRNG_State]
    mov rdx, rax
    shl rdx, 13
    xor rax, rdx
    mov rdx, rax
    shr rdx, 7
    xor rax, rdx
    mov rdx, rax
    shl rdx, 17
    xor rax, rdx
    mov qword ptr [g_Phone_PRNG_State], rax

    ; Normalize to a 10-digit number range (roughly)
    ; (rax % 9,000,000,000) + 1,000,000,000
    xor rdx, rdx
    mov rcx, 9000000000
    div rcx
    add rdx, 1000000000
    
    ; Save to structure
    mov qword ptr [rcx + OFF_PHONE_NUM], rdx
    mov rax, rdx
    ret
Sovereign_Phone_AssignNumber ENDP

; -----------------------------------------------------------------------------------------
; UINT32 Sovereign_Phone_Dial(void* pNetworkBase, UINT32 callerIdx, UINT64 targetNum)
; RCX = pNetworkBase (Start of 1024-player array)
; RDX = callerIdx (0-1023)
; R8  = targetNum
; Returns: 1 if ringing, 0 if busy/offline.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Phone_Dial
Sovereign_Phone_Dial PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    ; 1) Calculate Caller pointer
    mov rsi, rdx
    shl rsi, 6                     ; idx * 64
    add rsi, rcx                   ; RSI = Caller State Pointer

    ; 2) Search Directory for targetNum
    mov rdi, rcx                   ; Start of network array
    xor rbx, rbx                   ; Counter (0-1023)

@@SearchLoop:
    cmp rbx, 1024
    jae @@NotFound
    
    mov rax, qword ptr [rdi + OFF_PHONE_NUM]
    cmp rax, r8
    je @@FoundTarget
    
    add rdi, 64                    ; Next player block
    inc rbx
    jmp @@SearchLoop

@@FoundTarget:
    ; Check if target is busy (Status != IDLE)
    mov eax, dword ptr [rdi + OFF_CALL_STATUS]
    test eax, eax
    jnz @@Busy

    ; --- Initiate Call Handshake ---
    ; Set Target to RINGING_IN
    mov dword ptr [rdi + OFF_CALL_STATUS], STATUS_RINGING
    ; Track who is calling them (store caller's number in target's target field)
    mov rax, qword ptr [rsi + OFF_PHONE_NUM]
    mov qword ptr [rdi + OFF_CALL_TARGET], rax

    ; Set Caller to DIALING
    mov dword ptr [rsi + OFF_CALL_STATUS], STATUS_DIALING
    mov qword ptr [rsi + OFF_CALL_TARGET], r8

    mov rax, 1                     ; Success: Ringing
    jmp @@Exit

@@Busy:
@@NotFound:
    xor rax, rax                   ; Fail: Offline/Busy

@@Exit:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Phone_Dial ENDP

; -----------------------------------------------------------------------------------------
; VOID Sovereign_Phone_Hangup(void* pNetworkBase, UINT32 playerIdx)
; Resets both ends of the call to IDLE.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Phone_Hangup
Sovereign_Phone_Hangup PROC
    mov rax, rdx
    shl rax, 6
    add rax, rcx                   ; RAX = Player State Pointer

    ; Capture target number to find the other side
    mov r8, qword ptr [rax + OFF_CALL_TARGET]
    
    ; Reset local
    mov dword ptr [rax + OFF_CALL_STATUS], STATUS_IDLE
    mov qword ptr [rax + OFF_CALL_TARGET], 0

    ; Search-and-reset the other side of the call
    mov rdi, rcx
    xor rbx, rbx
@@FindPartner:
    cmp rbx, 1024
    jae @@Done
    mov rdx, qword ptr [rdi + OFF_PHONE_NUM]
    cmp rdx, r8
    je @@ResetPartner
    add rdi, 64
    inc rbx
    jmp @@FindPartner

@@ResetPartner:
    mov dword ptr [rdi + OFF_CALL_STATUS], STATUS_IDLE
    mov qword ptr [rdi + OFF_CALL_TARGET], 0

@@Done:
    ret
Sovereign_Phone_Hangup ENDP

; -----------------------------------------------------------------------------------------
; PROCEDURE: SendPhoneMessage
; Input: RCX = SenderIdx, RDX = TargetNum, R8 = MsgPtr
; -----------------------------------------------------------------------------------------
PUBLIC SendPhoneMessage
SendPhoneMessage PROC
    ; Logic: Queue for network dispatch
    ret
SendPhoneMessage ENDP

END