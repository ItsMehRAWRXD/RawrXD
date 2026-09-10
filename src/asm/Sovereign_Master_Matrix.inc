; Sovereign_Master_Matrix.inc — 100-slot master registry pool
IFNDEF SOVEREIGN_MASTER_MATRIX_INC
SOVEREIGN_MASTER_MATRIX_INC EQU 1

MAX_SLOTS EQU 100

; Component_Type
COMP_GGUF_ARENA     EQU 1
COMP_HOTPATCHER     EQU 2
COMP_UTIER_TRACE    EQU 3

; State_Flags bits
SF_ACTIVE           EQU 1
SF_LOCKED           EQU 2
SF_SEALED           EQU 4

SOVEREIGN_MASTER_POOL STRUCT
    Slot_ID         dq 0
    Component_Type  dq 0
    State_Flags     dq 0
    Base_Address    dq 0
    Virtual_Offset  dq 0
SOVEREIGN_MASTER_POOL ENDS

ENDIF ; SOVEREIGN_MASTER_MATRIX_INC
