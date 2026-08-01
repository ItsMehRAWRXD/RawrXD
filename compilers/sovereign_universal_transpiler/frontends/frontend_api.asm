; frontend_api.asm - Frontend ABI contract for Sovereign Universal Transpiler
; Every language adapter implements this interface

; External declarations from uir.asm
extrn UIRCreateContext:proc
extrn UIRCreateNode:proc
extrn UIRGetNode:proc
extrn UIRAddConstant:proc
extrn UIRGetConstant:proc
extrn UIRAddRelocation:proc
extrn UIRAllocVReg:proc
extrn UIRReset:proc
extrn UIRGetNodeCount:proc
extrn UIRValidateHeader:proc

; UIR Opcodes
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_MOVE         EQU 14

; Frontend ABI Contract:
; 
; FrontendCompile PROC
;   RCX = source buffer pointer
;   RDX = source size (bytes)
;   R8  = UIR output buffer pointer
;
; Returns:
;   RAX = UIR node count (0 on error)
;
; The frontend must:
;   1. Parse the source language syntax
;   2. Generate UIR nodes in the output buffer
;   3. Return the number of nodes generated
;
; The frontend must NOT:
;   - Call the backend directly
;   - Generate machine code
;   - Write files
;   - Allocate memory (use provided buffer)

.code

; FrontendCompile - Default no-op frontend
FrontendCompile PROC
    xor rax, rax           ; return 0 nodes
    ret
FrontendCompile ENDP

end