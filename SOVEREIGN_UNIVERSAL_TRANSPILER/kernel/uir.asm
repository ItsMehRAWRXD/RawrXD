; ============================================================================
; UIR.ASM - Universal Intermediate Representation
; Sovereign Universal Transpiler v0.1
; Pure MASM x64 - Zero Dependencies
; ============================================================================
; The UIR is the stable contract between all language frontends and backends.
; Every language compiles to UIR, then UIR compiles to native code.
; ============================================================================

OPTION CASEMAP:NONE

; ============================================================================
; UIR OPCODES - Minimal stable ABI
; ============================================================================
IR_NOP              EQU 0
IR_LOAD_CONST       EQU 1   ; Load constant value: a=const_ptr, b=type
IR_CALL             EQU 2   ; Call function: a=func_ptr, b=arg_count, c=arg_list
IR_RETURN           EQU 3   ; Return from function: a=value
IR_EXIT             EQU 4   ; Exit program: a=exit_code
IR_ADD              EQU 5   ; Add: a=dest, b=src1, c=src2
IR_SUB              EQU 6   ; Subtract: a=dest, b=src1, c=src2
IR_MUL              EQU 7   ; Multiply: a=dest, b=src1, c=src2
IR_DIV              EQU 8   ; Divide: a=dest, b=src1, c=src2
IR_MOV              EQU 9   ; Move: a=dest, b=src
IR_COMPARE          EQU 10  ; Compare: a=result, b=src1, c=src2
IR_BRANCH           EQU 11  ; Branch: a=target_node
IR_BRANCH_IF        EQU 12  ; Conditional branch: a=condition, b=target
IR_LABEL            EQU 13  ; Label marker: a=label_id
IR_STRING           EQU 14  ; String constant: a=string_ptr, b=length
IR_NUMBER           EQU 15  ; Number constant: a=value, b=type

; Value types
TYPE_VOID           EQU 0
TYPE_INT            EQU 1
TYPE_FLOAT          EQU 2
TYPE_STRING         EQU 3
TYPE_BOOL           EQU 4
TYPE_PTR            EQU 5

; ============================================================================
; UIR NODE STRUCTURE
; ============================================================================
UIR_NODE STRUCT
    opcode      DWORD ?     ; IR opcode
    flags       DWORD ?     ; Node flags
    operand0    QWORD ?     ; Primary operand
    operand1    QWORD ?     ; Secondary operand
    operand2    QWORD ?     ; Tertiary operand
    line        DWORD ?     ; Source line number
    column      DWORD ?     ; Source column
UIR_NODE ENDS

; ============================================================================
; UIR PROGRAM STRUCTURE
; ============================================================================
UIR_PROGRAM STRUCT
    nodes       QWORD ?     ; Pointer to node array
    node_count  QWORD ?     ; Number of nodes
    node_cap    QWORD ?     ; Capacity of node array
    constants   QWORD ?     ; Pointer to constant pool
    const_count QWORD ?     ; Number of constants
    strings     QWORD ?     ; Pointer to string table
    string_count QWORD ?    ; Number of strings
UIR_PROGRAM ENDS

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA
ALIGN 8

; Current program being built
current_program UIR_PROGRAM {}

; Node storage (pre-allocated for bootstrap)
node_buffer     DB 65536 DUP(0)   ; Space for ~1000 nodes
node_buffer_end DQ 0

; Constant pool
const_buffer    DB 32768 DUP(0)   ; Constants storage
const_buffer_end DQ 0

; String table
string_buffer   DB 65536 DUP(0)   ; String storage
string_buffer_end DQ 0

; Error messages
msg_uir_init    DB "[UIR] Universal IR initialized", 13, 10, 0
msg_node_create DB "[UIR] Node created: opcode=", 0
msg_program_end DB "[UIR] Program complete: ", 0
msg_nodes       DB " nodes", 13, 10, 0

; Number conversion buffer
number_buf      DB 32 DUP(0)

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ============================================================================
; UIR INITIALIZATION
; ============================================================================

; Initialize UIR system
; Returns: RAX = 0 on success
UIRInit PROC
    PUSH RBX
    
    ; Initialize program structure
    LEA RAX, node_buffer
    MOV current_program.nodes, RAX
    MOV current_program.node_count, 0
    MOV current_program.node_cap, 1000
    
    LEA RAX, const_buffer
    MOV current_program.constants, RAX
    MOV current_program.const_count, 0
    
    LEA RAX, string_buffer
    MOV current_program.strings, RAX
    MOV current_program.string_count, 0
    
    XOR RAX, RAX
    POP RBX
    RET
UIRInit ENDP

; ============================================================================
; NODE CREATION
; ============================================================================

; Create a new UIR node
; ECX = opcode
; Returns: RAX = pointer to new node
UIRCreateNode PROC
    PUSH RBX
    PUSH R12
    PUSH R13
    
    MOV R12D, ECX       ; Save opcode
    
    ; Get current node count
    MOV RBX, current_program.node_count
    CMP RBX, current_program.node_cap
    JAE .overflow
    
    ; Calculate node address
    MOV RAX, current_program.nodes
    IMUL R13, RBX, SIZEOF UIR_NODE
    ADD RAX, R13
    
    ; Initialize node
    MOV [RAX].UIR_NODE.opcode, R12D
    MOV [RAX].UIR_NODE.flags, 0
    MOV [RAX].UIR_NODE.operand0, 0
    MOV [RAX].UIR_NODE.operand1, 0
    MOV [RAX].UIR_NODE.operand2, 0
    MOV [RAX].UIR_NODE.line, 0
    MOV [RAX].UIR_NODE.column, 0
    
    ; Increment count
    INC current_program.node_count
    
    JMP .done
    
.overflow:
    XOR RAX, RAX    ; Return NULL on overflow
    
.done:
    POP R13
    POP R12
    POP RBX
    RET
UIRCreateNode ENDP

; Set node operands
; RCX = node pointer, EDX = op0, R8 = op1, R9 = op2
UIRSetOperands PROC
    MOV [RCX].UIR_NODE.operand0, RDX
    MOV [RCX].UIR_NODE.operand1, R8
    MOV [RCX].UIR_NODE.operand2, R9
    RET
UIRSetOperands ENDP

; Set node source location
; RCX = node pointer, EDX = line, R8D = column
UIRSetLocation PROC
    MOV [RCX].UIR_NODE.line, EDX
    MOV [RCX].UIR_NODE.column, R8D
    RET
UIRSetLocation ENDP

; ============================================================================
; CONSTANT POOL MANAGEMENT
; ============================================================================

; Add string constant to pool
; RCX = string pointer, EDX = length
; Returns: RAX = constant index
UIRAddString PROC
    PUSH RBX
    PUSH R12
    PUSH R13
    PUSH R14
    
    MOV R12, RCX        ; string pointer
    MOV R13D, EDX       ; length
    
    ; Get string buffer position
    MOV RAX, current_program.string_count
    MOV RBX, RAX
    IMUL R14, RBX, 1024 ; Max 1KB per string
    
    ; Copy string to buffer
    MOV RDI, current_program.strings
    ADD RDI, R14
    MOV RSI, R12
    MOV RCX, R13
    REP MOVSB
    MOV BYTE PTR [RDI], 0   ; Null terminate
    
    ; Increment count
    INC current_program.string_count
    
    ; Return index
    MOV RAX, RBX
    
    POP R14
    POP R13
    POP R12
    POP RBX
    RET
UIRAddString ENDP

; Add numeric constant
; RCX = value, EDX = type
; Returns: RAX = constant index
UIRAddNumber PROC
    PUSH RBX
    
    ; Get constant index
    MOV RBX, current_program.const_count
    
    ; Store in constant buffer (simplified)
    MOV RAX, current_program.constants
    IMUL RBX, RBX, 16
    MOV [RAX + RBX], RCX
    MOV [RAX + RBX + 8], EDX
    
    ; Increment and return index
    MOV RAX, current_program.const_count
    INC current_program.const_count
    
    POP RBX
    RET
UIRAddNumber ENDP

; ============================================================================
; UIR EMITTER HELPERS
; ============================================================================

; Emit NOP node
; Returns: RAX = node pointer
UIREmitNop PROC
    MOV ECX, IR_NOP
    CALL UIRCreateNode
    RET
UIREmitNop ENDP

; Emit LOAD_CONST
; RCX = const_index, EDX = type
; Returns: RAX = node pointer
UIREmitLoadConst PROC
    PUSH R12
    PUSH R13
    MOV R12, RCX
    MOV R13D, EDX
    
    MOV ECX, IR_LOAD_CONST
    CALL UIRCreateNode
    TEST RAX, RAX
    JZ .done
    
    MOV RCX, RAX
    MOV RDX, R12
    MOV R8, R13
    XOR R9, R9
    CALL UIRSetOperands
    
.done:
    POP R13
    POP R12
    RET
UIREmitLoadConst ENDP

; Emit CALL
; RCX = func_name_ptr, EDX = arg_count, R8 = arg_list
; Returns: RAX = node pointer
UIREmitCall PROC
    PUSH R12
    PUSH R13
    PUSH R14
    MOV R12, RCX
    MOV R13D, EDX
    MOV R14, R8
    
    MOV ECX, IR_CALL
    CALL UIRCreateNode
    TEST RAX, RAX
    JZ .done
    
    MOV RCX, RAX
    MOV RDX, R12
    MOV R8, R13
    MOV R9, R14
    CALL UIRSetOperands
    
.done:
    POP R14
    POP R13
    POP R12
    RET
UIREmitCall ENDP

; Emit EXIT
; RCX = exit_code
; Returns: RAX = node pointer
UIREmitExit PROC
    PUSH R12
    MOV R12, RCX
    
    MOV ECX, IR_EXIT
    CALL UIRCreateNode
    TEST RAX, RAX
    JZ .done
    
    MOV RCX, RAX
    MOV RDX, R12
    XOR R8, R8
    XOR R9, R9
    CALL UIRSetOperands
    
.done:
    POP R12
    RET
UIREmitExit ENDP

; Emit RETURN
; RCX = return_value
; Returns: RAX = node pointer
UIREmitReturn PROC
    PUSH R12
    MOV R12, RCX
    
    MOV ECX, IR_RETURN
    CALL UIRCreateNode
    TEST RAX, RAX
    JZ .done
    
    MOV RCX, RAX
    MOV RDX, R12
    XOR R8, R8
    XOR R9, R9
    CALL UIRSetOperands
    
.done:
    POP R12
    RET
UIREmitReturn ENDP

; ============================================================================
; UIR PROGRAM ACCESS
; ============================================================================

; Get node by index
; RCX = index
; Returns: RAX = node pointer (NULL if out of bounds)
UIRGetNode PROC
    CMP RCX, current_program.node_count
    JAE .out_of_bounds
    
    MOV RAX, current_program.nodes
    IMUL RCX, RCX, SIZEOF UIR_NODE
    ADD RAX, RCX
    RET
    
.out_of_bounds:
    XOR RAX, RAX
    RET
UIRGetNode ENDP

; Get node count
; Returns: RAX = node count
UIRGetNodeCount PROC
    MOV RAX, current_program.node_count
    RET
UIRGetNodeCount ENDP

; Get string from pool
; RCX = string index
; Returns: RAX = string pointer
UIRGetString PROC
    CMP RCX, current_program.string_count
    JAE .out_of_bounds
    
    MOV RAX, current_program.strings
    IMUL RCX, RCX, 1024
    ADD RAX, RCX
    RET
    
.out_of_bounds:
    XOR RAX, RAX
    RET
UIRGetString ENDP

; ============================================================================
; UIR DEBUG OUTPUT
; ============================================================================

; Print UIR program summary
UIRPrintSummary PROC
    PUSH RBX
    
    ; Print header
    LEA RCX, msg_program_end
    CALL PrintCString
    
    ; Print node count
    MOV RBX, current_program.node_count
    MOV ECX, EBX
    CALL PrintNumber
    
    LEA RCX, msg_nodes
    CALL PrintCString
    
    POP RBX
    RET
UIRPrintSummary ENDP

; ============================================================================
; UTILITY FUNCTIONS (minimal runtime)
; ============================================================================

; Print null-terminated string
; RCX = string pointer
PrintCString PROC
    PUSH RBX
    PUSH R12
    SUB RSP, 40H
    
    MOV R12, RCX
    
    ; Calculate length
    XOR EBX, EBX
    MOV RDI, R12
.count_loop:
    CMP BYTE PTR [RDI + RBX], 0
    JE .count_done
    INC EBX
    JMP .count_loop
.count_done:
    
    ; Get stdout
    MOV ECX, -11   ; STD_OUTPUT_HANDLE
    CALL GetStdHandle
    
    ; Write
    MOV RCX, RAX
    MOV RDX, R12
    MOV R8D, EBX
    LEA R9, [RSP+28H]
    MOV QWORD PTR [RSP+20H], 0
    CALL WriteFile
    
    ADD RSP, 40H
    POP R12
    POP RBX
    RET
PrintCString ENDP

; Print number
; ECX = number
PrintNumber PROC
    PUSH RBX
    PUSH R12
    SUB RSP, 28H
    
    MOV R12D, ECX
    LEA RBX, number_buf + 31
    MOV BYTE PTR [RBX], 0
    
    MOV EAX, R12D
    TEST EAX, EAX
    JNZ .convert
    MOV BYTE PTR [RBX-1], '0'
    DEC RBX
    JMP .print
    
.convert:
    TEST EAX, EAX
    JZ .print
    XOR EDX, EDX
    MOV ECX, 10
    DIV ECX
    ADD DL, '0'
    DEC RBX
    MOV [RBX], DL
    JMP .convert
    
.print:
    MOV RCX, RBX
    CALL PrintCString
    
    ADD RSP, 28H
    POP R12
    POP RBX
    RET
PrintNumber ENDP

; ============================================================================
; EXTERNAL IMPORTS
; ============================================================================
EXTRN GetStdHandle:PROC
EXTRN WriteFile:PROC

END
