; ============================================================================
; uir.asm - Universal Intermediate Representation
; Language-neutral compiler contract for Sovereign Universal Transpiler
; v0.2 - Adds UIR header, virtual registers, relocation table, validation
; ============================================================================

option casemap:none

; ----------------------------------------------------------------------------
; UIR Magic / Version - Used for validation
; ----------------------------------------------------------------------------
UIR_MAGIC       EQU 055494952h    ; "UIR\0" as little-endian DWORD
UIR_VERSION     EQU 00000002h     ; v0.2

; ----------------------------------------------------------------------------
; UIR Opcodes - Stable v0.1 ABI
; ----------------------------------------------------------------------------
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1      ; operand0 = const index, dst = vreg
IR_CALL         EQU 2      ; operand0 = function index, operand1 = arg vreg
IR_RETURN       EQU 3      ; operand0 = return vreg
IR_EXIT         EQU 4      ; operand0 = exit code vreg (or immediate)
IR_STORE_VAR    EQU 5      ; operand0 = var index, operand1 = src vreg
IR_LOAD_VAR     EQU 6      ; operand0 = var index, dst = vreg
IR_ADD          EQU 7      ; operand0 = vreg1, operand1 = vreg2, dst = vreg3
IR_SUB          EQU 8
IR_MUL          EQU 9
IR_DIV          EQU 10
IR_CMP          EQU 11     ; operand0 = vreg1, operand1 = vreg2
IR_BRANCH       EQU 12     ; operand0 = target node index
IR_BRANCH_COND  EQU 13     ; operand0 = cond vreg, operand1 = true, operand2 = false
IR_MOVE         EQU 14     ; operand0 = src vreg, dst = dst vreg

; ----------------------------------------------------------------------------
; UIR Node Flags
; ----------------------------------------------------------------------------
UIR_FLAG_NONE       EQU 0
UIR_FLAG_CONST      EQU 1     ; Node produces a constant
UIR_FLAG_DEAD       EQU 2     ; Node is dead (marked for removal)
UIR_FLAG_USED       EQU 4     ; Node result is used
UIR_FLAG_VOLATILE   EQU 8     ; Node has side effects (call, store)

; ----------------------------------------------------------------------------
; UIR Node Structure (32 bytes) - FIXED LAYOUT
; ----------------------------------------------------------------------------
UIR_NODE STRUCT
    opcode      DWORD ?
    flags       DWORD ?
    operand0    QWORD ?
    operand1    QWORD ?
    dst_vreg    DWORD ?      ; Destination virtual register (-1 = none)
    operand2    DWORD ?      ; Reduced to DWORD to fit in 32 bytes
UIR_NODE ENDS

; ----------------------------------------------------------------------------
; UIR Header (placed at start of UIR buffer)
; ----------------------------------------------------------------------------
UIR_HEADER STRUCT
    magic           DWORD ?     ; UIR_MAGIC
    version         DWORD ?     ; UIR_VERSION
    node_count      QWORD ?     ; Number of UIR nodes
    string_table    QWORD ?     ; Offset to string table in buffer
    string_count    QWORD ?     ; Number of strings
    func_table      QWORD ?     ; Offset to function table
    func_count      QWORD ?     ; Number of functions
    vreg_count      QWORD ?     ; Next virtual register to allocate
UIR_HEADER ENDS

; ----------------------------------------------------------------------------
; Relocation Record (for RIP-relative fixups)
; ----------------------------------------------------------------------------
UIR_RELOC STRUCT
    patch_offset    QWORD ?     ; Offset in .text where disp32 lives
    target_section  DWORD ?     ; 0=.text, 1=.rdata
    target_offset   QWORD ?     ; Offset in target section
    reloc_type      DWORD ?     ; 0=RIP32, 1=abs64
UIR_RELOC ENDS

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
    vreg_next   DWORD ?      ; Next virtual register to allocate
    reloc_table QWORD ?      ; Pointer to UIR_RELOC array
    reloc_count DWORD ?
    reloc_cap   DWORD ?
UIR_CONTEXT ENDS

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
uir_ctx UIR_CONTEXT {}

; Node array (max 64 nodes)
ALIGN 16
uir_nodes UIR_NODE 64 DUP(<>)

; Constant pool (max 64 constants, 512 bytes total)
ALIGN 16
uir_const_pool BYTE 512 DUP(0)

; Function table
ALIGN 16
uir_func_names QWORD 16 DUP(0)

; Relocation table (max 16 relocations)
ALIGN 16
uir_relocs UIR_RELOC 16 DUP(<>)

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; UIRValidateHeader - Validate a UIR buffer header
; RCX = pointer to UIR buffer (starts with UIR_HEADER)
; Returns: RAX = 1 if valid, 0 if invalid
; ============================================================================
UIRValidateHeader PROC
    push rbx
    
    ; Check magic
    mov eax, [rcx].UIR_HEADER.magic
    cmp eax, UIR_MAGIC
    jne uir_invalid
    
    ; Check version
    mov eax, [rcx].UIR_HEADER.version
    cmp eax, UIR_VERSION
    jne uir_invalid
    
    ; Check node count is reasonable
    mov rax, [rcx].UIR_HEADER.node_count
    cmp rax, 4096
    ja uir_invalid
    
    mov rax, 1
    jmp uir_done
    
uir_invalid:
    xor rax, rax
    
uir_done:
    pop rbx
    ret
UIRValidateHeader ENDP

; ============================================================================
; UIRAllocVReg - Allocate a new virtual register
; Returns: RAX = vreg index
; ============================================================================
UIRAllocVReg PROC
    mov eax, uir_ctx.vreg_next
    inc uir_ctx.vreg_next
    ret
UIRAllocVReg ENDP

; ============================================================================
; UIRAddRelocation - Add a relocation record
; RCX = patch offset in .text
; RDX = target section (0=.text, 1=.rdata)
; R8  = target offset
; R9  = reloc type (0=RIP32)
; Returns: RAX = reloc index (or -1 if full)
; ============================================================================
UIRAddRelocation PROC
    push rbx
    push rdi
    
    ; Check capacity
    mov eax, uir_ctx.reloc_count
    cmp eax, uir_ctx.reloc_cap
    jge reloc_full
    
    ; Calculate reloc address
    mov edi, eax
    imul edi, SIZEOF UIR_RELOC
    lea rdi, [uir_relocs + rdi]
    
    ; Fill reloc
    mov [rdi].UIR_RELOC.patch_offset, rcx
    mov [rdi].UIR_RELOC.target_section, edx
    mov [rdi].UIR_RELOC.target_offset, r8
    mov [rdi].UIR_RELOC.reloc_type, r9d
    
    ; Return index and increment
    mov eax, uir_ctx.reloc_count
    inc uir_ctx.reloc_count
    jmp reloc_done
    
reloc_full:
    mov rax, -1
    
reloc_done:
    pop rdi
    pop rbx
    ret
UIRAddRelocation ENDP

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
    mov uir_ctx.node_cap, 256
    
    lea rax, uir_const_pool
    mov uir_ctx.const_pool, rax
    mov uir_ctx.const_count, 0
    
    lea rax, uir_func_names
    mov uir_ctx.func_table, rax
    mov uir_ctx.func_count, 0
    
    ; Initialize relocation table
    lea rax, uir_relocs
    mov uir_ctx.reloc_table, rax
    mov uir_ctx.reloc_count, 0
    mov uir_ctx.reloc_cap, 64
    
    ; Initialize vreg counter
    mov uir_ctx.vreg_next, 0
    
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
; [RSP+28h] = dst_vreg (or -1)
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
    jge node_full
    
    ; Calculate node address using imul (doesn't clobber RDX)
    mov rdi, uir_ctx.nodes
    imul rax, rax, SIZEOF UIR_NODE
    add rdi, rax        ; RDI = &nodes[index]
    
    ; Fill node
    mov [rdi].UIR_NODE.opcode, ebx
    mov [rdi].UIR_NODE.flags, 0
    mov [rdi].UIR_NODE.operand0, rdx
    mov [rdi].UIR_NODE.operand1, r8
    mov dword ptr [rdi].UIR_NODE.operand2, r9d  ; Use r9d (32-bit) for operand2
    
    ; Set dst_vreg from stack param
    mov eax, [rbp + 48]
    mov [rdi].UIR_NODE.dst_vreg, eax
    
    ; Mark volatile opcodes
    cmp ebx, IR_CALL
    jne node_check_exit
    or dword ptr [rdi].UIR_NODE.flags, UIR_FLAG_VOLATILE
node_check_exit:
    cmp ebx, IR_EXIT
    jne node_check_store
    or dword ptr [rdi].UIR_NODE.flags, UIR_FLAG_VOLATILE
node_check_store:
    cmp ebx, IR_STORE_VAR
    jne node_flags_done
    or dword ptr [rdi].UIR_NODE.flags, UIR_FLAG_VOLATILE
node_flags_done:
    
    ; Return index and increment count
    mov eax, uir_ctx.node_count
    inc uir_ctx.node_count
    
    jmp node_done
    
node_full:
    mov rax, -1
    
node_done:
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
    
    ; Validate index (use unsigned compare)
    ; node_count is DWORD, so compare 32-bit
    mov eax, ecx
    cmp eax, uir_ctx.node_count
    jae getnode_invalid
    
    ; Calculate address: nodes + index * SIZEOF UIR_NODE
    ; Zero-extend index to 64-bit for address calculation
    mov rax, rcx              ; rcx is zero-extended by caller (upper 32 bits = 0)
    mov r8, rax
    imul r8, SIZEOF UIR_NODE
    mov rax, uir_ctx.nodes
    add rax, r8
    
    jmp getnode_done
    
getnode_invalid:
    xor rax, rax
    
getnode_done:
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
    jge const_full
    
    ; Calculate offset in const pool
    mov r8d, eax
    shl r8d, 8
    mov rdi, uir_ctx.const_pool
    add rdi, r8
    mov rcx, rbx
    rep movsb
    
    ; Return index
    mov eax, uir_ctx.const_count
    inc uir_ctx.const_count
    
    jmp const_done
    
const_full:
    mov rax, -1
    
const_done:
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
    jae getconst_invalid
    
    ; Calculate address (index * 256)
    mov eax, ecx
    shl eax, 8
    add rax, uir_ctx.const_pool
    
    jmp getconst_done
    
getconst_invalid:
    xor rax, rax
    
getconst_done:
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
