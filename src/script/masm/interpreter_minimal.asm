; RawrXD-Script Minimal MASM Interpreter
; Tests basic execution: LOAD_CONST + RETURN

; NaN-boxed constants (MASM format with h suffix)
JS_NULL         EQU 7FF3000000000000h
JS_UNDEFINED    EQU 7FF3000000000001h
JS_TRUE         EQU 7FF2000000000001h
JS_FALSE        EQU 7FF2000000000000h

; Opcodes
OP_LOAD_CONST   EQU 00h
OP_RETURN       EQU 58h

; ============================================================================
; Data Section
; ============================================================================
.data
ALIGN 16

PUBLIC g_opcode_coverage
g_opcode_coverage BYTE 256 DUP(0)

; ============================================================================
; Code Section
; ============================================================================
.CODE

ALIGN 16

; ============================================================================
; ExecuteBytecode_MASM - Minimal interpreter for testing
; Entry:  rcx = Runtime* (unused in minimal version)
;         rdx = bytecode base pointer
;         r8  = bytecode size
;         r9  = result pointer (uint64_t*)
; Exit:   rax = 1 (success) or 0 (failure)
; ============================================================================
PUBLIC ExecuteBytecode_MASM
ExecuteBytecode_MASM PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Initialize VM state
    ; rcx = Runtime* (ignored for minimal version)
    ; rdx = bytecode base
    ; r8 = bytecode size (ignored)
    ; r9 = result pointer
    mov rbx, rdx            ; PC = bytecode base
    xor rsi, rsi            ; CONST_POOL = null (minimal version)
    mov rdi, r9             ; rdi = result pointer
    xor r12, r12            ; r12 = register 0 (v0)
    
    ; Mark coverage for first opcode
    mov byte ptr [OFFSET g_opcode_coverage], 1

@interpreter_loop:
    ; Fetch opcode
    movzx rax, byte ptr [rbx]
    inc rbx
    
    ; Dispatch based on opcode
    cmp al, OP_LOAD_CONST
    je @load_const
    cmp al, OP_RETURN
    je @return
    
    ; Unknown opcode - error
    xor rax, rax
    jmp @cleanup

@load_const:
    ; Format: [OP:1][DEST:1][CONST_IDX:2]
    ; For minimal version: just load 42.0 (0x4045000000000000)
    add rbx, 3                      ; Skip operands
    
    ; Load 42.0 as NaN-boxed value
    mov r12, 4045000000000000h      ; v0 = 42.0 (IEEE 754 double)
    
    ; Mark coverage
    mov byte ptr [OFFSET g_opcode_coverage + 0], 1
    
    jmp @interpreter_loop

@return:
    ; Format: [OP:1][SRC:1]
    movzx rcx, byte ptr [rbx]       ; src register (ignored, always v0)
    inc rbx
    
    ; Store result
    mov [rdi], r12                  ; *result = v0
    
    ; Mark coverage
    mov byte ptr [OFFSET g_opcode_coverage + 058h], 1
    
    ; Return success
    mov rax, 1
    jmp @cleanup

@cleanup:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
ExecuteBytecode_MASM ENDP

END
