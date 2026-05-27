; =============================================================================
; FILE: Sovereign_Prediction_Core.asm
; PURPOSE:
;   Deterministic client prediction + rollback core.
;   Pure fixed-point state replication.
;
; FEATURES:
;   - Circular prediction history
;   - Authoritative rewind
;   - Deterministic replay
;   - Input/state parity validation
;   - Tick-perfect rollback
;
; NO:
;   - CRT
;   - Heap
;   - Floating point
;   - STL
;
; =============================================================================

OPTION CASEMAP:NONE

PUBLIC Sovereign_Predict_Init
PUBLIC Sovereign_Predict_Save
PUBLIC Sovereign_Predict_Reconcile
PUBLIC Sovereign_Predict_Replay

EXTERN Sovereign_Tape_Read:PROC
EXTERN Sovereign_Input_Poll:PROC

; =============================================================================
; CONSTANTS
; =============================================================================

PRED_HISTORY_MAX       EQU 256
STATE_SIZE             EQU 128
INPUT_FRAME_SIZE       EQU 20

; =============================================================================
; STRUCTURES
; =============================================================================

PredictedState STRUCT
    tick_id            DD ?
    crc                DD ?
    state_blob         DB STATE_SIZE DUP(?)
PredictedState ENDS

; =============================================================================
; DATA
; =============================================================================

.DATA

ALIGN 16

Prediction_Write_Index     DD 0
Prediction_Replay_Index    DD 0

ALIGN 16

Prediction_History:
PredictedState PRED_HISTORY_MAX DUP(<0>)

ALIGN 16

Replay_Input_Frame DB INPUT_FRAME_SIZE DUP(0)

; =============================================================================
; CODE
; =============================================================================

.CODE

; =============================================================================
; Sovereign_Predict_Init
; =============================================================================
Sovereign_Predict_Init PROC

    xor eax, eax

    mov [Prediction_Write_Index], eax
    mov [Prediction_Replay_Index], eax

    ret

Sovereign_Predict_Init ENDP

; =============================================================================
; Sovereign_Predict_Save
;
; RCX = state ptr
; EDX = tick id
;
; =============================================================================
Sovereign_Predict_Save PROC

    push rbx
    push rsi
    push rdi

    mov eax, [Prediction_Write_Index]

    and eax, (PRED_HISTORY_MAX - 1)

    mov ebx, SIZEOF PredictedState
    imul eax, ebx

    lea rdi, Prediction_History
    add rdi, rax

    mov [rdi + PredictedState.tick_id], edx

    ; =========================================================================
    ; copy state
    ; =========================================================================
    
    ; preserve rcx (state ptr) since rep movsb overwrites it
    push rcx

    lea rdi, [rdi + PredictedState.state_blob]
    mov rsi, rcx

    mov ecx, STATE_SIZE
    rep movsb
    
    ; restore rcx for crc
    pop rcx

    ; =========================================================================
    ; crc
    ; =========================================================================

    mov r8d, 2166136261
    xor r9d, r9d

L_crc_loop:

    movzx eax, byte ptr [rcx + r9]
    xor r8d, eax
    imul r8d, 16777619

    inc r9d
    cmp r9d, STATE_SIZE
    jl L_crc_loop

    mov [rdi - STATE_SIZE - 4], r8d

    inc dword ptr [Prediction_Write_Index]

    pop rdi
    pop rsi
    pop rbx

    ret

Sovereign_Predict_Save ENDP

; =============================================================================
; Sovereign_Predict_Reconcile
;
; RCX = authoritative state ptr
; EDX = authoritative tick
; R8D = authoritative crc
;
; RETURNS:
;   EAX = 1 mismatch
;   EAX = 0 match
;
; =============================================================================
Sovereign_Predict_Reconcile PROC

    push rbx

    mov eax, edx
    and eax, (PRED_HISTORY_MAX - 1)

    mov ebx, SIZEOF PredictedState
    imul eax, ebx

    lea r10, Prediction_History
    add r10, rax

    cmp dword ptr [r10 + PredictedState.tick_id], edx
    jne L_desync

    cmp dword ptr [r10 + PredictedState.crc], r8d
    jne L_desync

    xor eax, eax
    jmp L_reconcile_exit

L_desync:

    mov [Prediction_Replay_Index], edx

    mov eax, 1

L_reconcile_exit:

    pop rbx
    ret

Sovereign_Predict_Reconcile ENDP

; =============================================================================
; Sovereign_Predict_Replay
;
; RCX = simulation callback
;
; =============================================================================
Sovereign_Predict_Replay PROC

    push rbx
    push rsi
    push rdi
    push r12

    mov r12, rcx

L_replay_begin:

    mov eax, [Prediction_Replay_Index]
    cmp eax, [Prediction_Write_Index]
    jge L_replay_done

    ; =========================================================================
    ; read deterministic input frame
    ; =========================================================================

    lea rcx, Replay_Input_Frame
    call Sovereign_Tape_Read

    test eax, eax
    jz L_replay_done

    ; =========================================================================
    ; invoke simulation callback
    ;
    ; RCX = input frame
    ; =========================================================================

    lea rcx, Replay_Input_Frame
    call r12

    inc dword ptr [Prediction_Replay_Index]

    jmp L_replay_begin

L_replay_done:

    pop r12
    pop rdi
    pop rsi
    pop rbx

    ret

Sovereign_Predict_Replay ENDP

END