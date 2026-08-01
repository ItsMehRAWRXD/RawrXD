; ============================================================================
; kernel/wasm_encoder.asm - WebAssembly Binary Encoder
; Zero-dependency WASM module synthesis
; ============================================================================

option casemap:none

PUBLIC WASM_EncodeHeader
PUBLIC WASM_EncodeSection
PUBLIC WASM_EncodeTypeSection
PUBLIC WASM_EncodeFuncSection
PUBLIC WASM_EncodeExportSection
PUBLIC WASM_EncodeCodeSection
PUBLIC WASM_EncodeI32Const
PUBLIC WASM_EncodeI64Const
PUBLIC WASM_EncodeF32Const
PUBLIC WASM_EncodeF64Const
PUBLIC WASM_EncodeLocalGet
PUBLIC WASM_EncodeLocalSet
PUBLIC WASM_EncodeGlobalGet
PUBLIC WASM_EncodeGlobalSet
PUBLIC WASM_EncodeI32Add
PUBLIC WASM_EncodeI32Sub
PUBLIC WASM_EncodeI32Mul
PUBLIC WASM_EncodeI32DivS
PUBLIC WASM_EncodeI64Add
PUBLIC WASM_EncodeF32Add
PUBLIC WASM_EncodeF32Mul
PUBLIC WASM_EncodeF64Add
PUBLIC WASM_EncodeF64Mul
PUBLIC WASM_EncodeCall
PUBLIC WASM_EncodeCallIndirect
PUBLIC WASM_EncodeIf
PUBLIC WASM_EncodeElse
PUBLIC WASM_EncodeEnd
PUBLIC WASM_EncodeReturn
PUBLIC WASM_EncodeBr
PUBLIC WASM_EncodeBrIf
PUBLIC WASM_EncodeBlock
PUBLIC WASM_EncodeLoop
PUBLIC WASM_EncodeMemoryGrow
PUBLIC WASM_EncodeMemorySize

; WASM Type Constants
WASM_TYPE_I32     EQU 07Fh
WASM_TYPE_I64     EQU 07Eh
WASM_TYPE_F32     EQU 07Dh
WASM_TYPE_F64     EQU 07Ch
WASM_TYPE_VOID    EQU 040h
WASM_TYPE_FUNCREF EQU 070h
WASM_TYPE_EXTERNREF EQU 06Fh

; WASM Section IDs
WASM_SEC_CUSTOM   EQU 00h
WASM_SEC_TYPE     EQU 01h
WASM_SEC_IMPORT   EQU 02h
WASM_SEC_FUNC     EQU 03h
WASM_SEC_TABLE    EQU 04h
WASM_SEC_MEMORY   EQU 05h
WASM_SEC_GLOBAL   EQU 06h
WASM_SEC_EXPORT   EQU 07h
WASM_SEC_START    EQU 08h
WASM_SEC_ELEM     EQU 09h
WASM_SEC_CODE     EQU 0Ah
WASM_SEC_DATA     EQU 0Bh
WASM_SEC_DATA_COUNT EQU 0Ch

; WASM Opcodes
WASM_OP_UNREACHABLE EQU 00h
WASM_OP_NOP         EQU 01h
WASM_OP_BLOCK       EQU 02h
WASM_OP_LOOP        EQU 03h
WASM_OP_IF          EQU 04h
WASM_OP_ELSE        EQU 05h
WASM_OP_END         EQU 0Bh
WASM_OP_BR          EQU 0Ch
WASM_OP_BR_IF       EQU 0Dh
WASM_OP_RETURN      EQU 0Fh
WASM_OP_CALL        EQU 10h
WASM_OP_CALL_INDIRECT EQU 11h
WASM_OP_LOCAL_GET   EQU 20h
WASM_OP_LOCAL_SET   EQU 21h
WASM_OP_LOCAL_TEE   EQU 22h
WASM_OP_GLOBAL_GET  EQU 23h
WASM_OP_GLOBAL_SET  EQU 24h
WASM_OP_I32_LOAD    EQU 28h
WASM_OP_I32_STORE   EQU 36h
WASM_OP_MEMORY_SIZE EQU 3Fh
WASM_OP_MEMORY_GROW EQU 40h
WASM_OP_I32_CONST   EQU 41h
WASM_OP_I64_CONST   EQU 42h
WASM_OP_F32_CONST   EQU 43h
WASM_OP_F64_CONST   EQU 44h
WASM_OP_I32_ADD     EQU 6Ah
WASM_OP_I32_SUB     EQU 6Bh
WASM_OP_I32_MUL     EQU 6Ch
WASM_OP_I32_DIV_S   EQU 6Dh
WASM_OP_I64_ADD     EQU 7Ch
WASM_OP_F32_ADD     EQU 92h
WASM_OP_F32_MUL     EQU 94h
WASM_OP_F64_ADD     EQU A0h
WASM_OP_F64_MUL     EQU A2h

.code

; ============================================================================
; WASM_EncodeHeader - Write WASM magic number and version
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeHeader PROC
    mov dword ptr [rcx], 06D736100h    ; "\0asm" magic
    mov dword ptr [rcx + 4], 1         ; Version 1
    lea rax, [rcx + 8]
    ret
WASM_EncodeHeader ENDP

; ============================================================================
; WASM_EncodeSection - Write section header
; RCX = Output buffer, EDX = Section ID, R8D = Section size
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeSection PROC
    mov byte ptr [rcx], dl         ; Section ID
    mov byte ptr [rcx + 1], r8b    ; Section size (LEB128, simplified)
    lea rax, [rcx + 2]
    ret
WASM_EncodeSection ENDP

; ============================================================================
; WASM_EncodeTypeSection - Write function type section
; RCX = Output buffer, EDX = Num types
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeTypeSection PROC
    push rbx
    mov rbx, rcx
    
    ; Section header
    mov byte ptr [rbx], WASM_SEC_TYPE
    mov byte ptr [rbx + 1], 5      ; Section size
    mov byte ptr [rbx + 2], 1      ; 1 type
    
    ; Function type: () -> i32
    mov byte ptr [rbx + 3], 060h   ; Func type marker
    mov byte ptr [rbx + 4], 0      ; 0 params
    mov byte ptr [rbx + 5], 1      ; 1 result
    mov byte ptr [rbx + 6], WASM_TYPE_I32
    
    lea rax, [rbx + 7]
    pop rbx
    ret
WASM_EncodeTypeSection ENDP

; ============================================================================
; WASM_EncodeFuncSection - Write function section
; RCX = Output buffer, EDX = Num functions
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeFuncSection PROC
    mov byte ptr [rcx], WASM_SEC_FUNC
    mov byte ptr [rcx + 1], 2      ; Section size
    mov byte ptr [rcx + 2], 1      ; 1 function
    mov byte ptr [rcx + 3], 0      ; Type index 0
    lea rax, [rcx + 4]
    ret
WASM_EncodeFuncSection ENDP

; ============================================================================
; WASM_EncodeExportSection - Write export section
; RCX = Output buffer, EDX = Function index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeExportSection PROC
    push rbx
    mov rbx, rcx
    
    mov byte ptr [rbx], WASM_SEC_EXPORT
    mov byte ptr [rbx + 1], 8      ; Section size
    mov byte ptr [rbx + 2], 1      ; 1 export
    mov byte ptr [rbx + 3], 4      ; Name length
    mov dword ptr [rbx + 4], 06E69616Dh  ; "main"
    mov byte ptr [rbx + 8], 0      ; Export kind (func)
    mov byte ptr [rbx + 9], dl     ; Function index
    
    lea rax, [rbx + 10]
    pop rbx
    ret
WASM_EncodeExportSection ENDP

; ============================================================================
; WASM_EncodeCodeSection - Write code section header
; RCX = Output buffer, EDX = Code size
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeCodeSection PROC
    mov byte ptr [rcx], WASM_SEC_CODE
    mov byte ptr [rcx + 1], dl     ; Section size
    mov byte ptr [rcx + 2], 1      ; 1 function body
    lea rax, [rcx + 3]
    ret
WASM_EncodeCodeSection ENDP

; ============================================================================
; WASM_EncodeI32Const - Encode i32.const instruction
; RCX = Output buffer, EDX = Value
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI32Const PROC
    mov byte ptr [rcx], WASM_OP_I32_CONST
    mov byte ptr [rcx + 1], dl     ; Value (LEB128, simplified for small values)
    lea rax, [rcx + 2]
    ret
WASM_EncodeI32Const ENDP

; ============================================================================
; WASM_EncodeI64Const - Encode i64.const instruction
; RCX = Output buffer, RDX = Value
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI64Const PROC
    mov byte ptr [rcx], WASM_OP_I64_CONST
    mov qword ptr [rcx + 1], rdx   ; Value (LEB128, simplified)
    lea rax, [rcx + 9]
    ret
WASM_EncodeI64Const ENDP

; ============================================================================
; WASM_EncodeF32Const - Encode f32.const instruction
; RCX = Output buffer, XMM0 = Value
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF32Const PROC
    mov byte ptr [rcx], WASM_OP_F32_CONST
    movss dword ptr [rcx + 1], xmm0
    lea rax, [rcx + 5]
    ret
WASM_EncodeF32Const ENDP

; ============================================================================
; WASM_EncodeF64Const - Encode f64.const instruction
; RCX = Output buffer, XMM0 = Value
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF64Const PROC
    mov byte ptr [rcx], WASM_OP_F64_CONST
    movsd qword ptr [rcx + 1], xmm0
    lea rax, [rcx + 9]
    ret
WASM_EncodeF64Const ENDP

; ============================================================================
; WASM_EncodeLocalGet - Encode local.get instruction
; RCX = Output buffer, EDX = Local index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeLocalGet PROC
    mov byte ptr [rcx], WASM_OP_LOCAL_GET
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeLocalGet ENDP

; ============================================================================
; WASM_EncodeLocalSet - Encode local.set instruction
; RCX = Output buffer, EDX = Local index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeLocalSet PROC
    mov byte ptr [rcx], WASM_OP_LOCAL_SET
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeLocalSet ENDP

; ============================================================================
; WASM_EncodeGlobalGet - Encode global.get instruction
; RCX = Output buffer, EDX = Global index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeGlobalGet PROC
    mov byte ptr [rcx], WASM_OP_GLOBAL_GET
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeGlobalGet ENDP

; ============================================================================
; WASM_EncodeGlobalSet - Encode global.set instruction
; RCX = Output buffer, EDX = Global index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeGlobalSet PROC
    mov byte ptr [rcx], WASM_OP_GLOBAL_SET
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeGlobalSet ENDP

; ============================================================================
; WASM_EncodeI32Add - Encode i32.add instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI32Add PROC
    mov byte ptr [rcx], WASM_OP_I32_ADD
    lea rax, [rcx + 1]
    ret
WASM_EncodeI32Add ENDP

; ============================================================================
; WASM_EncodeI32Sub - Encode i32.sub instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI32Sub PROC
    mov byte ptr [rcx], WASM_OP_I32_SUB
    lea rax, [rcx + 1]
    ret
WASM_EncodeI32Sub ENDP

; ============================================================================
; WASM_EncodeI32Mul - Encode i32.mul instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI32Mul PROC
    mov byte ptr [rcx], WASM_OP_I32_MUL
    lea rax, [rcx + 1]
    ret
WASM_EncodeI32Mul ENDP

; ============================================================================
; WASM_EncodeI32DivS - Encode i32.div_s instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI32DivS PROC
    mov byte ptr [rcx], WASM_OP_I32_DIV_S
    lea rax, [rcx + 1]
    ret
WASM_EncodeI32DivS ENDP

; ============================================================================
; WASM_EncodeI64Add - Encode i64.add instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeI64Add PROC
    mov byte ptr [rcx], WASM_OP_I64_ADD
    lea rax, [rcx + 1]
    ret
WASM_EncodeI64Add ENDP

; ============================================================================
; WASM_EncodeF32Add - Encode f32.add instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF32Add PROC
    mov byte ptr [rcx], WASM_OP_F32_ADD
    lea rax, [rcx + 1]
    ret
WASM_EncodeF32Add ENDP

; ============================================================================
; WASM_EncodeF32Mul - Encode f32.mul instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF32Mul PROC
    mov byte ptr [rcx], WASM_OP_F32_MUL
    lea rax, [rcx + 1]
    ret
WASM_EncodeF32Mul ENDP

; ============================================================================
; WASM_EncodeF64Add - Encode f64.add instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF64Add PROC
    mov byte ptr [rcx], WASM_OP_F64_ADD
    lea rax, [rcx + 1]
    ret
WASM_EncodeF64Add ENDP

; ============================================================================
; WASM_EncodeF64Mul - Encode f64.mul instruction
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeF64Mul PROC
    mov byte ptr [rcx], WASM_OP_F64_MUL
    lea rax, [rcx + 1]
    ret
WASM_EncodeF64Mul ENDP

; ============================================================================
; WASM_EncodeCall - Encode call instruction
; RCX = Output buffer, EDX = Function index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeCall PROC
    mov byte ptr [rcx], WASM_OP_CALL
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeCall ENDP

; ============================================================================
; WASM_EncodeCallIndirect - Encode call_indirect instruction
; RCX = Output buffer, EDX = Table index, R8D = Type index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeCallIndirect PROC
    mov byte ptr [rcx], WASM_OP_CALL_INDIRECT
    mov byte ptr [rcx + 1], r8b    ; Type index
    mov byte ptr [rcx + 2], dl     ; Table index
    mov byte ptr [rcx + 3], 0      ; Reserved
    lea rax, [rcx + 4]
    ret
WASM_EncodeCallIndirect ENDP

; ============================================================================
; WASM_EncodeIf - Encode if block
; RCX = Output buffer, EDX = Block type
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeIf PROC
    mov byte ptr [rcx], WASM_OP_IF
    mov byte ptr [rcx + 1], dl     ; Block type
    lea rax, [rcx + 2]
    ret
WASM_EncodeIf ENDP

; ============================================================================
; WASM_EncodeElse - Encode else
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeElse PROC
    mov byte ptr [rcx], WASM_OP_ELSE
    lea rax, [rcx + 1]
    ret
WASM_EncodeElse ENDP

; ============================================================================
; WASM_EncodeEnd - Encode end
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeEnd PROC
    mov byte ptr [rcx], WASM_OP_END
    lea rax, [rcx + 1]
    ret
WASM_EncodeEnd ENDP

; ============================================================================
; WASM_EncodeReturn - Encode return
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeReturn PROC
    mov byte ptr [rcx], WASM_OP_RETURN
    lea rax, [rcx + 1]
    ret
WASM_EncodeReturn ENDP

; ============================================================================
; WASM_EncodeBr - Encode br (unconditional branch)
; RCX = Output buffer, EDX = Label index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeBr PROC
    mov byte ptr [rcx], WASM_OP_BR
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeBr ENDP

; ============================================================================
; WASM_EncodeBrIf - Encode br_if (conditional branch)
; RCX = Output buffer, EDX = Label index
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeBrIf PROC
    mov byte ptr [rcx], WASM_OP_BR_IF
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeBrIf ENDP

; ============================================================================
; WASM_EncodeBlock - Encode block
; RCX = Output buffer, EDX = Block type
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeBlock PROC
    mov byte ptr [rcx], WASM_OP_BLOCK
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeBlock ENDP

; ============================================================================
; WASM_EncodeLoop - Encode loop
; RCX = Output buffer, EDX = Block type
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeLoop PROC
    mov byte ptr [rcx], WASM_OP_LOOP
    mov byte ptr [rcx + 1], dl
    lea rax, [rcx + 2]
    ret
WASM_EncodeLoop ENDP

; ============================================================================
; WASM_EncodeMemorySize - Encode memory.size
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeMemorySize PROC
    mov byte ptr [rcx], WASM_OP_MEMORY_SIZE
    mov byte ptr [rcx + 1], 0      ; Memory index
    lea rax, [rcx + 2]
    ret
WASM_EncodeMemorySize ENDP

; ============================================================================
; WASM_EncodeMemoryGrow - Encode memory.grow
; RCX = Output buffer
; Returns: RAX = Updated buffer pointer
; ============================================================================
WASM_EncodeMemoryGrow PROC
    mov byte ptr [rcx], WASM_OP_MEMORY_GROW
    mov byte ptr [rcx + 1], 0      ; Memory index
    lea rax, [rcx + 2]
    ret
WASM_EncodeMemoryGrow ENDP

END
