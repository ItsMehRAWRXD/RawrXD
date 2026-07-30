; ============================================================================
; Universal Intermediate Representation (UIR)
; Language-agnostic compiler intermediate
; ============================================================================

; IR Node Types
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_ADD          EQU 5
IR_SUB          EQU 6
IR_MUL          EQU 7
IR_DIV          EQU 8
IR_COMPARE      EQU 9
IR_BRANCH       EQU 10
IR_LABEL        EQU 11

; Value Types
VAL_NONE        EQU 0
VAL_INTEGER     EQU 1
VAL_STRING      EQU 2
VAL_BOOLEAN     EQU 3
VAL_VARIABLE    EQU 4
VAL_FUNCTION    EQU 5

; IR Node Structure
IR_NODE STRUCT
    opcode      DWORD ?
    value_type  DWORD ?
    operand1    QWORD ?
    operand2    QWORD ?
    result      QWORD ?
    next_node   QWORD ?
IR_NODE ENDS

; Value Structure
VALUE STRUCT
    type        DWORD ?
    int_val     QWORD ?
    str_ptr     QWORD ?
    str_len     QWORD ?
VALUE ENDS

; Function Structure
IR_FUNCTION STRUCT
    name        QWORD ?
    param_count DWORD ?
    local_count DWORD ?
    entry_node  QWORD ?
    next_func   QWORD ?
IR_FUNCTION ENDS

; Program Structure
IR_PROGRAM STRUCT
    functions   QWORD ?
    constants   QWORD ?
    strings     QWORD ?
    main_func   QWORD ?
IR_PROGRAM ENDS

; UIR Builder Functions
UIR_CreateNode PROTO
UIR_AddNode PROTO
UIR_CreateFunction PROTO
UIR_AddConstant PROTO
UIR_CreateProgram PROTO
UIR_DestroyProgram PROTO
