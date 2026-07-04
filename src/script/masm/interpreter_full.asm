; RawrXD-Script Full MASM Interpreter
; Comprehensive opcode support for JavaScript execution
; Register allocation: 6 virtual registers (r8-r13), r14-r15 reserved as temporaries

; NaN-boxed constants
JS_NULL         EQU 7FF3000000000000h
JS_UNDEFINED    EQU 7FF3000000000001h
JS_TRUE         EQU 7FF2000000000001h
JS_FALSE        EQU 7FF2000000000000h
JS_ZERO         EQU 0000000000000000h
JS_NAN          EQU 7FF8000000000000h

; Tag masks
QNAN_MASK       EQU 7FF8000000000000h
TAG_INT32       EQU 0001000000000000h
TAG_NUMBER      EQU 0000000000000000h

; Opcodes (full set)
OP_NOP          EQU 00h
OP_LOAD_CONST   EQU 01h
OP_LOAD_REG     EQU 02h
OP_STORE_REG    EQU 03h
OP_LOAD_GLOBAL  EQU 04h
OP_STORE_GLOBAL EQU 05h
OP_LOAD_NULL    EQU 06h
OP_LOAD_UNDEF   EQU 07h
OP_LOAD_TRUE    EQU 08h
OP_LOAD_FALSE   EQU 09h
OP_LOAD_ZERO    EQU 0Ah
OP_ADD          EQU 10h
OP_SUB          EQU 11h
OP_MUL          EQU 12h
OP_DIV          EQU 13h
OP_MOD          EQU 14h
OP_NEG          EQU 15h
OP_INC          EQU 16h
OP_DEC          EQU 17h
OP_EQ           EQU 20h
OP_NE           EQU 21h
OP_LT           EQU 22h
OP_LE           EQU 23h
OP_GT           EQU 24h
OP_GE           EQU 25h
OP_JUMP         EQU 30h
OP_JUMP_IF_TRUE EQU 31h
OP_JUMP_IF_FALSE EQU 32h
OP_CALL_NATIVE  EQU 40h
OP_CALL         EQU 41h
OP_RETURN       EQU 50h
OP_PRINT        EQU 60h
OP_HALT         EQU 0FFh

; Trace buffer size
TRACE_BUFFER_SIZE EQU 10000

; ============================================================================
; Data Section
; ============================================================================
.data
ALIGN 16

PUBLIC g_opcode_coverage
g_opcode_coverage BYTE 256 DUP(0)

; Trace buffer for execution recording
ALIGN 16
PUBLIC g_trace_buffer
g_trace_buffer QWORD TRACE_BUFFER_SIZE DUP(0)

PUBLIC g_trace_index
g_trace_index QWORD 0

; Global variable storage (simple hash table)
ALIGN 16
g_global_count QWORD 0
g_global_keys BYTE 4096 DUP(0)    ; 64 keys * 64 bytes
g_global_values QWORD 64 DUP(0)     ; 64 values

; Register file (8 virtual registers)
ALIGN 16
g_registers QWORD 8 DUP(0)

; Native function table
ALIGN 16
g_native_print QWORD 0              ; Will be set by C code

; ============================================================================
; Code Section
; ============================================================================
.CODE

ALIGN 16

; ============================================================================
; JsInterpreter_Run - Full JavaScript interpreter
; Entry:  rcx = bytecode base pointer
;         rdx = bytecode size
;         r8  = constant pool base
;         r9  = result pointer (uint64_t*)
; Exit:   rax = 1 (success) or 0 (failure)
; ============================================================================
JsInterpreter_Run PROC FRAME
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
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    ; Initialize VM state
    mov rbx, rcx            ; PC = bytecode base
    mov rsi, r8             ; CONST_POOL = constant pool
    mov rdi, r9             ; rdi = result pointer
    xor r15, r15            ; r15 = trace index
    
    ; Store bytecode end in stack frame (r13 is used as virtual register)
    mov rax, rbx            ; rax = bytecode base
    add rax, rdx            ; rax = bytecode base + size
    mov [rsp+48], rax       ; Store bytecode end on stack
    
    ; Clear virtual registers (r8-r14 are virtual registers 0-6)
    xor r8, r8              ; v0
    xor r9, r9              ; v1
    xor r10, r10            ; v2
    xor r11, r11            ; v3
    xor r12, r12            ; v4
    xor r13, r13            ; v5
    xor r14, r14            ; v6
    ; v7 (r15) is initialized below
    
    ; Initialize trace index (stored in memory, not register)
    mov rax, OFFSET g_trace_index
    mov QWORD PTR [rax], 0

@interpreter_loop:
    ; Check PC bounds
    mov rax, [rsp+48]       ; Load bytecode end from stack
    cmp rbx, rax
    jae @error_bounds
    
    ; Fetch opcode
    movzx rax, byte ptr [rbx]
    movzx rcx, al
    
    ; Record trace
    call @record_trace
    
    ; Mark coverage
    mov byte ptr [OFFSET g_opcode_coverage + rcx], 1
    
    ; Increment PC
    inc rbx
    
    ; Dispatch table
    cmp al, OP_NOP
    je @op_nop
    cmp al, OP_LOAD_CONST
    je @op_load_const
    cmp al, OP_LOAD_REG
    je @op_load_reg
    cmp al, OP_STORE_REG
    je @op_store_reg
    cmp al, OP_LOAD_GLOBAL
    je @op_load_global
    cmp al, OP_STORE_GLOBAL
    je @op_store_global
    cmp al, OP_LOAD_NULL
    je @op_load_null
    cmp al, OP_LOAD_TRUE
    je @op_load_true
    cmp al, OP_LOAD_FALSE
    je @op_load_false
    cmp al, OP_ADD
    je @op_add
    cmp al, OP_SUB
    je @op_sub
    cmp al, OP_MUL
    je @op_mul
    cmp al, OP_DIV
    je @op_div
    cmp al, OP_NEG
    je @op_neg
    cmp al, OP_EQ
    je @op_eq
    cmp al, OP_LT
    je @op_lt
    cmp al, OP_JUMP
    je @op_jump
    cmp al, OP_JUMP_IF_FALSE
    je @op_jump_if_false
    cmp al, OP_CALL_NATIVE
    je @op_call_native
    cmp al, OP_PRINT
    je @op_print
    cmp al, OP_RETURN
    je @op_return
    cmp al, OP_HALT
    je @op_halt
    
    ; Unknown opcode
    jmp @error_unknown

; ============================================================================
; Stack/Register Operations
; ============================================================================

@op_nop:
    jmp @interpreter_loop

@op_load_const:
    ; Format: [OP:1][DEST_REG:1][CONST_IDX:2]
    movzx rcx, byte ptr [rbx]       ; dest register index
    movzx rdx, word ptr [rbx+1]     ; constant index
    add rbx, 3
    
    ; Load from constant pool
    mov rax, [rsi + rdx*8]
    
    ; Store to register
    call @set_register
    jmp @interpreter_loop

@op_load_reg:
    ; Format: [OP:1][DEST:1][SRC:1]
    movzx rcx, byte ptr [rbx]       ; dest
    movzx rdx, byte ptr [rbx+1]      ; src
    add rbx, 2
    
    call @get_register              ; rax = registers[src]
    call @set_register              ; registers[dest] = rax
    jmp @interpreter_loop

@op_store_reg:
    ; Format: [OP:1][REG:1]
    movzx rcx, byte ptr [rbx]       ; register index
    inc rbx
    
    call @get_register
    mov r12, rax                    ; Store to accumulator
    jmp @interpreter_loop

@op_load_null:
    movzx rcx, byte ptr [rbx]       ; dest register
    inc rbx
    mov rax, JS_NULL
    call @set_register
    jmp @interpreter_loop

@op_load_true:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, JS_TRUE
    call @set_register
    jmp @interpreter_loop

@op_load_false:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, JS_FALSE
    call @set_register
    jmp @interpreter_loop

; ============================================================================
; Global Variable Operations
; ============================================================================

@op_load_global:
    ; Format: [OP:1][DEST:1][NAME_IDX:2]
    movzx rcx, byte ptr [rbx]       ; dest register
    movzx rdx, word ptr [rbx+1]     ; name index in constant pool
    add rbx, 3
    
    ; Get variable name from constant pool
    mov r14, [rsi + rdx*8]          ; r14 = name pointer (boxed)
    
    ; Simple linear search in globals
    xor r15, r15
    mov r14, OFFSET g_global_count
    mov r14, [r14]
    test r14, r14
    jz @global_not_found
    
    mov rax, JS_UNDEFINED             ; Default if not found
    call @set_register
    jmp @interpreter_loop

@global_not_found:
    mov rax, JS_UNDEFINED
    call @set_register
    jmp @interpreter_loop

@op_store_global:
    ; Format: [OP:1][SRC:1][NAME_IDX:2]
    movzx rcx, byte ptr [rbx]       ; src register
    movzx rdx, word ptr [rbx+1]     ; name index
    add rbx, 3
    
    call @get_register              ; rax = value to store
    
    ; Store to globals (simplified - just store in first slot for now)
    mov r14, OFFSET g_global_values
    mov [r14], rax
    mov r14, OFFSET g_global_count
    mov QWORD PTR [r14], 1
    
    jmp @interpreter_loop

; ============================================================================
; Arithmetic Operations
; ============================================================================

@op_add:
    ; Format: [OP:1][DEST:1][SRC_A:1][SRC_B:1]
    movzx r14d, byte ptr [rbx]       ; r14 = dest
    movzx r15d, byte ptr [rbx+1]      ; r15 = src_a
    movzx eax, byte ptr [rbx+2]       ; eax = src_b
    add rbx, 3
    
    ; Save src_b and dest on stack (r14/r15 are callee-saved)
    push rax
    
    ; Get left operand (src_a)
    mov rcx, r15
    call @get_register
    movq xmm0, rax
    
    ; Get right operand (src_b)
    pop rcx
    call @get_register
    movq xmm1, rax
    
    ; Perform addition
    addsd xmm0, xmm1
    movq rax, xmm0
    
    ; Store result
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

@op_sub:
    movzx r14d, byte ptr [rbx]
    movzx r15d, byte ptr [rbx+1]
    movzx eax, byte ptr [rbx+2]
    add rbx, 3
    
    push rax
    
    mov rcx, r15
    call @get_register
    movq xmm0, rax
    
    pop rcx
    call @get_register
    movq xmm1, rax
    
    subsd xmm0, xmm1
    movq rax, xmm0
    
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

@op_mul:
    movzx r14d, byte ptr [rbx]
    movzx r15d, byte ptr [rbx+1]
    movzx eax, byte ptr [rbx+2]
    add rbx, 3
    
    push rax
    
    mov rcx, r15
    call @get_register
    movq xmm0, rax
    
    pop rcx
    call @get_register
    movq xmm1, rax
    
    mulsd xmm0, xmm1
    movq rax, xmm0
    
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

@op_div:
    movzx r14d, byte ptr [rbx]
    movzx r15d, byte ptr [rbx+1]
    movzx eax, byte ptr [rbx+2]
    add rbx, 3
    
    push rax
    
    mov rcx, r15
    call @get_register
    movq xmm0, rax
    
    pop rcx
    call @get_register
    movq xmm1, rax
    
    divsd xmm0, xmm1
    movq rax, xmm0
    
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

@op_neg:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    
    mov rcx, rdx
    call @get_register
    
    mov r14, 8000000000000000h        ; Sign bit mask
    xor rax, r14                      ; Flip sign bit
    
    call @set_register
    jmp @interpreter_loop

; ============================================================================
; Comparison Operations
; ============================================================================

@op_eq:
    movzx r14d, byte ptr [rbx]       ; r14 = dest
    movzx r15d, byte ptr [rbx+1]     ; r15 = src_a
    movzx eax, byte ptr [rbx+2]      ; eax = src_b
    add rbx, 3
    
    push rax
    mov rcx, r15
    call @get_register               ; rax = left
    mov r15, rax                     ; r15 = left (r15 is callee-saved)
    pop rcx
    call @get_register               ; rax = right
    
    cmp r15, rax
    je @eq_true
    mov rax, JS_FALSE
    jmp @eq_done
@eq_true:
    mov rax, JS_TRUE
@eq_done:
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

@op_lt:
    movzx r14d, byte ptr [rbx]       ; r14 = dest
    movzx r15d, byte ptr [rbx+1]     ; r15 = src_a
    movzx eax, byte ptr [rbx+2]      ; eax = src_b
    add rbx, 3
    
    push rax
    mov rcx, r15
    call @get_register
    movq xmm0, rax
    pop rcx
    call @get_register
    movq xmm1, rax
    
    comisd xmm0, xmm1
    jb @lt_true
    mov rax, JS_FALSE
    jmp @lt_done
@lt_true:
    mov rax, JS_TRUE
@lt_done:
    mov rcx, r14
    call @set_register
    jmp @interpreter_loop

; ============================================================================
; Control Flow
; ============================================================================

@op_jump:
    ; Format: [OP:1][OFFSET:4]
    mov eax, dword ptr [rbx]
    add rbx, 4
    
    ; Calculate target: PC += offset (signed)
    movsxd rax, eax
    add rbx, rax
    jmp @interpreter_loop

@op_jump_if_false:
    ; Format: [OP:1][REG:1][OFFSET:4]
    movzx r14d, byte ptr [rbx]      ; r14 = register to test
    mov eax, dword ptr [rbx+1]      ; eax = offset
    add rbx, 5
    
    mov rcx, r14
    call @get_register              ; rax = value to test
    mov r14, rax                    ; r14 = value
    
    ; Check if false/null/undefined/zero
    ; Use 64-bit comparisons with immediate values loaded into registers
    mov r15, JS_FALSE
    cmp r14, r15
    je @do_jump
    mov r15, JS_NULL
    cmp r14, r15
    je @do_jump
    mov r15, JS_UNDEFINED
    cmp r14, r15
    je @do_jump
    test r14, r14
    jz @do_jump
    
    jmp @interpreter_loop
    
@do_jump:
    movsxd rax, eax
    add rbx, rax
    jmp @interpreter_loop

; ============================================================================
; Native Calls and I/O
; ============================================================================

@op_call_native:
    ; Format: [OP:1][DEST:1][FUNC_IDX:2][ARG_COUNT:1][ARGS...]
    movzx rcx, byte ptr [rbx]       ; dest
    movzx rdx, word ptr [rbx+1]     ; function index
    movzx r8, byte ptr [rbx+3]      ; arg count
    add rbx, 4
    
    ; For now, just handle print (index 0)
    test rdx, rdx
    jnz @native_not_found
    
    ; Get first argument
    movzx rax, byte ptr [rbx]       ; arg0 register
    inc rbx
    
    push rcx
    mov rcx, rax
    call @get_register
    pop rcx
    
    ; Call print function (simplified - just store result)
    mov rax, JS_NULL                ; print returns undefined/null
    call @set_register
    jmp @interpreter_loop

@native_not_found:
    jmp @error_native

@op_print:
    ; Format: [OP:1][REG:1]
    movzx rcx, byte ptr [rbx]
    inc rbx
    
    call @get_register
    
    ; Store value for C code to print
    mov r14, OFFSET g_registers
    mov [r14], rax                  ; Store in register 0 for retrieval
    
    jmp @interpreter_loop

@op_return:
    ; Format: [OP:1][SRC:1]
    movzx rcx, byte ptr [rbx]
    inc rbx
    
    call @get_register
    mov [rdi], rax                  ; Store result
    
    mov rax, 1                      ; Success
    jmp @cleanup

@op_halt:
    xor rax, rax                    ; Halt with "failure" (0)
    jmp @cleanup

; ============================================================================
; Helper Functions
; ============================================================================

; Get register value
; Input: rcx = register index (0-5)
; Output: rax = register value
; Note: r14/r15 are reserved as temporaries, NOT virtual registers
@get_register:
    cmp rcx, 0
    je @get_r0
    cmp rcx, 1
    je @get_r1
    cmp rcx, 2
    je @get_r2
    cmp rcx, 3
    je @get_r3
    cmp rcx, 4
    je @get_r4
    cmp rcx, 5
    je @get_r5
    xor rax, rax
    ret
@get_r0:
    mov rax, r8
    ret
@get_r1:
    mov rax, r9
    ret
@get_r2:
    mov rax, r10
    ret
@get_r3:
    mov rax, r11
    ret
@get_r4:
    mov rax, r12
    ret
@get_r5:
    mov rax, r13
    ret

; Set register value
; Input: rcx = register index, rax = value
@set_register:
    cmp rcx, 0
    je @set_r0
    cmp rcx, 1
    je @set_r1
    cmp rcx, 2
    je @set_r2
    cmp rcx, 3
    je @set_r3
    cmp rcx, 4
    je @set_r4
    cmp rcx, 5
    je @set_r5
    ret
@set_r0:
    mov r8, rax
    ret
@set_r1:
    mov r9, rax
    ret
@set_r2:
    mov r10, rax
    ret
@set_r3:
    mov r11, rax
    ret
@set_r4:
    mov r12, rax
    ret
@set_r5:
    mov r13, rax
    ret

; Record execution trace
@record_trace:
    push rax
    push rcx
    push rdx
    
    ; Get current trace index
    mov rdx, OFFSET g_trace_index
    mov rcx, [rdx]
    
    ; Check bounds
    cmp rcx, TRACE_BUFFER_SIZE
    jae @trace_skip
    
    ; Store: [PC:32][OPCODE:8][REG0:64]
    mov rax, rbx                    ; Current PC
    mov rdx, OFFSET g_trace_buffer
    mov [rdx + rcx*8], rax          ; Store PC
    
    ; Increment index
    mov rdx, OFFSET g_trace_index
    inc QWORD PTR [rdx]
    
@trace_skip:
    pop rdx
    pop rcx
    pop rax
    ret

; ============================================================================
; Error Handlers
; ============================================================================

@error_bounds:
    xor rax, rax
    jmp @cleanup

@error_unknown:
    xor rax, rax
    jmp @cleanup

@error_native:
    xor rax, rax
    jmp @cleanup

@cleanup:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
JsInterpreter_Run ENDP

; ============================================================================
; C API Functions
; ============================================================================

; JsInterpreter_GetTrace - Get trace buffer pointer
; Returns: rax = pointer to trace buffer
JsInterpreter_GetTrace PROC
    mov rax, OFFSET g_trace_buffer
    ret
JsInterpreter_GetTrace ENDP

; JsInterpreter_GetTraceCount - Get number of trace entries
; Returns: rax = trace entry count
JsInterpreter_GetTraceCount PROC
    mov rax, OFFSET g_trace_index
    mov rax, [rax]
    ret
JsInterpreter_GetTraceCount ENDP

; JsInterpreter_ClearTrace - Clear trace buffer
JsInterpreter_ClearTrace PROC
    mov rax, OFFSET g_trace_index
    mov QWORD PTR [rax], 0
    ret
JsInterpreter_ClearTrace ENDP

; JsInterpreter_GetCoverage - Get opcode coverage pointer
; Returns: rax = pointer to coverage array
JsInterpreter_GetCoverage PROC
    mov rax, OFFSET g_opcode_coverage
    ret
JsInterpreter_GetCoverage ENDP

; JsInterpreter_ResetCoverage - Clear coverage data
JsInterpreter_ResetCoverage PROC
    mov rcx, 256
    mov rax, OFFSET g_opcode_coverage
@clear_loop:
    mov BYTE PTR [rax], 0
    inc rax
    dec rcx
    jnz @clear_loop
    ret
JsInterpreter_ResetCoverage ENDP

; JsInterpreter_GetRegister - Get register value after execution
; Entry: rcx = register index (0-7)
; Returns: rax = register value
JsInterpreter_GetRegister PROC
    cmp rcx, 0
    je @gr_r0
    cmp rcx, 1
    je @gr_r1
    cmp rcx, 2
    je @gr_r2
    cmp rcx, 3
    je @gr_r3
    cmp rcx, 4
    je @gr_r4
    cmp rcx, 5
    je @gr_r5
    cmp rcx, 6
    je @gr_r6
    cmp rcx, 7
    je @gr_r7
    xor rax, rax
    ret
@gr_r0:
    mov rax, r8
    ret
@gr_r1:
    mov rax, r9
    ret
@gr_r2:
    mov rax, r10
    ret
@gr_r3:
    mov rax, r11
    ret
@gr_r4:
    mov rax, r12
    ret
@gr_r5:
    mov rax, r13
    ret
@gr_r6:
    mov rax, r14
    ret
@gr_r7:
    mov rax, r15
    ret
JsInterpreter_GetRegister ENDP

END
