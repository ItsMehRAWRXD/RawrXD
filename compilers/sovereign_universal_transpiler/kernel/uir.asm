; ============================================================================
; uir.asm - Universal Intermediate Representation
; Language-neutral compiler contract for Sovereign Universal Transpiler
; ============================================================================

option casemap:none
option win64:3

; ----------------------------------------------------------------------------
; UIR Opcodes - Stable v0.1 ABI
; ----------------------------------------------------------------------------
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1      ; operand0 = const index
IR_CALL         EQU 2      ; operand0 = function index, operand1 = arg count
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_STORE_VAR    EQU 5      ; operand0 = var index
IR_LOAD_VAR     EQU 6      ; operand0 = var index
IR_ADD          EQU 7
IR_SUB          EQU 8
IR_MUL          EQU 9
IR_DIV          EQU 10

; ----------------------------------------------------------------------------
; UIR Node Structure
; ----------------------------------------------------------------------------
UIR_NODE STRUCT
    opcode      DWORD ?
    flags       DWORD ?
    operand0    QWORD ?
    operand1    QWORD ?
    operand2    QWORD ?
UIR_NODE ENDS

; ----------------------------------------------------------------------------
; UIR Context
; ----------------------------------------------------------------------------
UIR_CONTEXT STRUCT
    nodes       QWORD ?      ; Pointer to UIR_NODE array
    node_count  DWORD ?
    node_cap    DWORD ?
    const_pool  QWORD ?      ; Pointer to constant strings
    const_count DWORD ?
    func_table  QWORD ?      ; Function name table
    func_count  DWORD ?
UIR_CONTEXT ENDS

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
uir_ctx UIR_CONTEXT {}

; Node array (max 4096 nodes)
ALIGN 16
uir_nodes UIR_NODE 4096 DUP(<>)

; Constant pool (max 256 constants, 64KB total)
ALIGN 16
uir_const_pool BYTE 65536 DUP(0)

; Function table
ALIGN 16
uir_func_names QWORD 256 DUP(0)

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; UIRCreateContext - Initialize UIR context
; ============================================================================
UIRCreateContext PROC
    push rbp
    mov rbp, rsp
    
    ; Initialize context
    lea rax, uir_nodes
    mov uir_ctx.nodes, rax
    mov uir_ctx.node_count, 0
    mov uir_ctx.node_cap, 4096
    
    lea rax, uir_const_pool
    mov uir_ctx.const_pool, rax
    mov uir_ctx.const_count, 0
    
    lea rax, uir_func_names
    mov uir_ctx.func_table, rax
    mov uir_ctx.func_count, 0
    
    mov rax, 1      ; Success
    leave
    ret
UIRCreateContext ENDP

; ============================================================================
; UIRCreateNode - Create a new UIR node
; RCX = opcode
; RDX = operand0
; R8  = operand1
; R9  = operand2
; Returns: RAX = node index (or -1 if full)
; ============================================================================
UIRCreateNode PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    
    mov ebx, ecx        ; Save opcode
    
    ; Check capacity
    mov eax, uir_ctx.node_count
    cmp eax, uir_ctx.node_cap
    jge .full
    
    ; Calculate node address
    mov rdi, uir_ctx.nodes
    mov ecx, SIZEOF UIR_NODE
    mul ecx             ; RAX = index * sizeof(UIR_NODE)
    add rdi, rax        ; RDI = &nodes[index]
    
    ; Fill node
    mov [rdi].UIR_NODE.opcode, ebx
    mov [rdi].UIR_NODE.flags, 0
    mov [rdi].UIR_NODE.operand0, rdx
    mov [rdi].UIR_NODE.operand1, r8
    mov [rdi].UIR_NODE.operand2, r9
    
    ; Return index and increment count
    mov eax, uir_ctx.node_count
    inc uir_ctx.node_count
    
    jmp .done
    
.full:
    mov rax, -1
    
.done:
    pop rdi
    pop rbx
    leave
    ret
UIRCreateNode ENDP

; ============================================================================
; UIRGetNode - Get pointer to node by index
; RCX = node index
; Returns: RAX = pointer to UIR_NODE (or NULL if invalid)
; ============================================================================
UIRGetNode PROC
    push rbp
    mov rbp, rsp
    
    ; Validate index
    cmp ecx, uir_ctx.node_count
    jae .invalid
    
    ; Calculate address
    mov rax, uir_ctx.nodes
    mov r8d, SIZEOF UIR_NODE
    mul r8d             ; RAX = index * sizeof(UIR_NODE)
    add rax, uir_ctx.nodes
    
    jmp .done
    
.invalid:
    xor rax, rax
    
.done:
    leave
    ret
UIRGetNode ENDP

; ============================================================================
; UIRAddConstant - Add string constant to pool
; RCX = string pointer
; RDX = string length
; Returns: RAX = constant index (or -1 if full)
; ============================================================================
UIRAddConstant PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx        ; Source string
    mov ebx, edx        ; Length
    
    ; Check capacity
    mov eax, uir_ctx.const_count
    cmp eax, 256
    jge .full
    
    ; Calculate offset in const pool
    ; For simplicity, use fixed 256-byte slots
    mov edi, eax
    shl edi, 8          ; index * 256
    
    ; Copy string
    mov rcx, rbx        ; Length
    mov rdi, uir_ctx.const_pool
    add rdi, rdi        ; RDI = destination
    rep movsb
    
    ; Return index
    mov eax, uir_ctx.const_count
    inc uir_ctx.const_count
    
    jmp .done
    
.full:
    mov rax, -1
    
.done:
    pop rdi
    pop rsi
    pop rbx
    leave
    ret
UIRAddConstant ENDP

; ============================================================================
; UIRGetConstant - Get pointer to constant by index
; RCX = constant index
; Returns: RAX = pointer to string (or NULL if invalid)
; ============================================================================
UIRGetConstant PROC
    push rbp
    mov rbp, rsp
    
    ; Validate index
    cmp ecx, uir_ctx.const_count
    jae .invalid
    
    ; Calculate address (index * 256)
    mov eax, ecx
    shl eax, 8
    add rax, uir_ctx.const_pool
    
    jmp .done
    
.invalid:
    xor rax, rax
    
.done:
    leave
    ret
UIRGetConstant ENDP

; ============================================================================
; UIRReset - Clear all nodes (keep constants)
; ============================================================================
UIRReset PROC
    push rbp
    mov rbp, rsp
    
    mov uir_ctx.node_count, 0
    
    mov rax, 1
    leave
    ret
UIRReset ENDP

; ============================================================================
; UIRGetNodeCount - Get current node count
; Returns: RAX = node count
; ============================================================================
UIRGetNodeCount PROC
    push rbp
    mov rbp, rsp
    
    mov eax, uir_ctx.node_count
    
    leave
    ret
UIRGetNodeCount ENDP

END
