; ==================================================================================
; INIT DAG - DETERMINISTIC SYSTEM BOOT GRAPH
; ==================================================================================

.DATA
ALIGN 64
InitGraphState QWORD 0
InitLock       DWORD 0

.CODE

PUBLIC Sovereign_DAG_Initialize

Sovereign_DAG_Initialize PROC
    ENTER_FRAME
    CLEAR_SHADOW

    ; lock init DAG
    ACQUIRE_LOCK InitLock

    ; --------------------------
    ; STAGE 0: HW INIT
    ; --------------------------
    test InitGraphState, 1
    jnz skip0
    or InitGraphState, 1
    ; HW init hook
skip0:

    ; --------------------------
    ; STAGE 1: SECURITY
    ; --------------------------
    test InitGraphState, 2
    jnz skip1
    or InitGraphState, 2
    ; security init hook
skip1:

    ; --------------------------
    ; STAGE 2: SYSCALL READY
    ; --------------------------
    test InitGraphState, 4
    jnz skip2
    or InitGraphState, 4
skip2:

    RELEASE_LOCK InitLock

    EXIT_FRAME
Sovereign_DAG_Initialize ENDP
