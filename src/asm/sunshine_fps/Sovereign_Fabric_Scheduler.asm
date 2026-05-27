; ==============================================================================
; SOVEREIGN_FABRIC_SCHEDULER.ASM
; Static entry points for the 16-lane execution matrix.
; ==============================================================================
INCLUDE Sovereign_Types.inc

_TEXT SEGMENT 'CODE'
    EXTERN Sovereign_Lane_Entry : PROC
    
    ; Define each lane as a unique entry point for the thread launcher.
    ; This ensures we have discrete symbols for debugging and static mapping.

    PUBLIC Lane_Entry_1
    PUBLIC Lane_Entry_2
    PUBLIC Lane_Entry_3
    PUBLIC Lane_Entry_4
    PUBLIC Lane_Entry_5
    PUBLIC Lane_Entry_6
    PUBLIC Lane_Entry_7
    PUBLIC Lane_Entry_8
    PUBLIC Lane_Entry_9
    PUBLIC Lane_Entry_10
    PUBLIC Lane_Entry_11
    PUBLIC Lane_Entry_12
    PUBLIC Lane_Entry_13
    PUBLIC Lane_Entry_14
    PUBLIC Lane_Entry_15

Lane_Entry_1 PROC
    mov rcx, 1
    jmp Sovereign_Lane_Entry
Lane_Entry_1 ENDP

Lane_Entry_2 PROC
    mov rcx, 2
    jmp Sovereign_Lane_Entry
Lane_Entry_2 ENDP

Lane_Entry_3 PROC
    mov rcx, 3
    jmp Sovereign_Lane_Entry
Lane_Entry_3 ENDP

Lane_Entry_4 PROC
    mov rcx, 4
    jmp Sovereign_Lane_Entry
Lane_Entry_4 ENDP

Lane_Entry_5 PROC
    mov rcx, 5
    jmp Sovereign_Lane_Entry
Lane_Entry_5 ENDP

Lane_Entry_6 PROC
    mov rcx, 6
    jmp Sovereign_Lane_Entry
Lane_Entry_6 ENDP

Lane_Entry_7 PROC
    mov rcx, 7
    jmp Sovereign_Lane_Entry
Lane_Entry_7 ENDP

Lane_Entry_8 PROC
    mov rcx, 8
    jmp Sovereign_Lane_Entry
Lane_Entry_8 ENDP

Lane_Entry_9 PROC
    mov rcx, 9
    jmp Sovereign_Lane_Entry
Lane_Entry_9 ENDP

Lane_Entry_10 PROC
    mov rcx, 10
    jmp Sovereign_Lane_Entry
Lane_Entry_10 ENDP

Lane_Entry_11 PROC
    mov rcx, 11
    jmp Sovereign_Lane_Entry
Lane_Entry_11 ENDP

Lane_Entry_12 PROC
    mov rcx, 12
    jmp Sovereign_Lane_Entry
Lane_Entry_12 ENDP

Lane_Entry_13 PROC
    mov rcx, 13
    jmp Sovereign_Lane_Entry
Lane_Entry_13 ENDP

Lane_Entry_14 PROC
    mov rcx, 14
    jmp Sovereign_Lane_Entry
Lane_Entry_14 ENDP

Lane_Entry_15 PROC
    mov rcx, 15
    jmp Sovereign_Lane_Entry
Lane_Entry_15 ENDP

_DATA SEGMENT
    PUBLIC Sovereign_Lane_Table
    ALIGN 8
    Sovereign_Lane_Table DQ 0 ; Lane 0 runs on main thread
    DQ OFFSET Lane_Entry_1
    DQ OFFSET Lane_Entry_2
    DQ OFFSET Lane_Entry_3
    DQ OFFSET Lane_Entry_4
    DQ OFFSET Lane_Entry_5
    DQ OFFSET Lane_Entry_6
    DQ OFFSET Lane_Entry_7
    DQ OFFSET Lane_Entry_8
    DQ OFFSET Lane_Entry_9
    DQ OFFSET Lane_Entry_10
    DQ OFFSET Lane_Entry_11
    DQ OFFSET Lane_Entry_12
    DQ OFFSET Lane_Entry_13
    DQ OFFSET Lane_Entry_14
    DQ OFFSET Lane_Entry_15
_DATA ENDS

_TEXT ENDS
END
