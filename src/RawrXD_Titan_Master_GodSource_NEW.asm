; ============================================================================
; RawrXD_Titan_Master_GodSource_NEW.asm - The Final Entry Point
; Transitioned to Non-Kernel / Zero-IAT Architecture
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

EXTERN Sovereign_PEB_Bootstrap : PROC
EXTERN Sovereign_Heap_Init      : PROC
EXTERN Sovereign_IPC_Bootstrap   : PROC
EXTERN Sovereign_LoadModel_Disk  : PROC
EXTERN Sovereign_Initialize_All_Systems : PROC
EXTERN Sovereign_Update_Gameplay_Tick   : PROC
EXTERN TITAN_LOOP                : PROC

.DATA
    model_path db "codestral22b.gguf", 0
    
    ; Canonical Definitions for Runtime Globals
    g_ApiTable SOVEREIGN_API_TABLE <>
    g_GovState GOV_STATE <>
    g_ModelState MODEL_STATE <>
    g_TPS TPS_WORKSPACE <>

    PUBLIC g_ApiTable
    PUBLIC g_GovState
    PUBLIC g_ModelState
    PUBLIC g_TPS

    g_pGov dq OFFSET g_GovState
    g_pTPS dq OFFSET g_TPS
    PUBLIC g_pGov
    PUBLIC g_pTPS

.CODE

; Entry Point
mainCRTStartup PROC
    sub rsp, 40

    ; 1. Resolve APIs via PEB (No IAT)
    call Sovereign_PEB_Bootstrap
    
    ; 2. Initialize Self-Managed Heap
    call Sovereign_Heap_Init

    ; 3. System Initialization
    call Sovereign_IPC_Bootstrap
    call Sovereign_Initialize_All_Systems

    ; 4. Load Model
    lea rcx, model_path
    call Sovereign_LoadModel_Disk
    test rax, rax
    jz _ExitFailure

    ; 5. Enter Production Loop
    call TITAN_LOOP

    xor rax, rax
    add rsp, 40
    ret

_ExitFailure:
    mov rcx, -1
    call [g_ApiTable.pExitProcess]
    add rsp, 40
    ret
mainCRTStartup ENDP

END
