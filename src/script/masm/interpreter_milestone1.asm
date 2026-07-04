; RawrXD-Script MASM Interpreter - Milestone 1 Minimal Version
; Pure x64 MASM - Zero Dependencies
; Only implements: LOAD_INT, RETURN

.CODE

; ============================================================================
; ExecuteBytecode_MASM - C-compatible entry point for Milestone 1
; Entry:  rcx = Runtime* (opaque pointer, contains arena/state)
;         rdx = bytecode pointer
;         r8  = bytecode length
;         r9  = result pointer (uint64_t*)
; Exit:   rax = 1 (success) or 0 (failure)
;         [r9] = result value (if success)
; ============================================================================
ExecuteBytecode_MASM PROC FRAME
    ; Save non-volatile registers
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
    
    ; Save result pointer for later
    mov [rsp + 48], r9
    
    ; Set up execution context
    mov rsi, rdx            ; rsi = bytecode start
    mov r12, rdx            ; r12 = PC = bytecode start
    add r12, r8             ; r12 = bytecode end
    
    ; Set up arena from Runtime
    mov r13, [rcx]          ; ARENA_BASE = runtime->arenaBase
    mov r14, [rcx + 8]      ; BUMP = runtime->arenaBump
    mov r15, rcx            ; Save Runtime* for later
    
    ; Set up execution state
    mov rbx, rdx            ; PC = bytecode start
    xor rdi, rdi            ; CONST_POOL = null
    xor r8, r8              ; v0 = 0
    xor r9, r9              ; v1 = 0
    xor r10, r10            ; v2 = 0
    xor r11, r11            ; v3 = 0
    
    ; Initialize frame pointer
    mov rbp, rsp
    sub rbp, 64

; ============================================================================
; Main Interpreter Loop
; ============================================================================
ALIGN 16
interpreter_loop:
    ; Bounds check: PC < bytecode_end
    cmp rbx, r12
    jae execution_complete
    
    ; Fetch opcode and advance PC
    movzx rax, byte ptr [rbx]
    inc rbx
    
    ; Simple switch on opcode
    cmp rax, 0
    je op_load_const
    cmp rax, 1
    je op_load_int
    cmp rax, 50h
    je op_return
    
    ; Unknown opcode - return error
    jmp error_unknown_opcode

; ---------------------------------------------------------------------------
; OP_LOAD_INT (01h): Load 32-bit immediate into register
; Format: OP_LOAD_INT <int32> <dst_reg>
; ---------------------------------------------------------------------------
op_load_int:
    ; Bounds check for operands (need 5 more bytes from current PC)
    lea rdx, [rbx + 5]
    cmp rdx, r12
    ja error_truncated
    
    ; Read int32 (little-endian)
    mov eax, dword ptr [rbx]
    add rbx, 4
    
    ; Read destination register
    movzx rcx, byte ptr [rbx]
    inc rbx
    
    ; Encode as NaN-boxed int32: 7FF8000400000000h | (value & FFFFFFFFh)
    ; C++ format: kNaNMask (7FF8000000000000h) | (kTagInt32 << 32) | value
    mov rdx, 07FF8000400000000h             ; QNaN mask | TAG_INT32 in bits 32-35
    and rax, 0FFFFFFFFh                     ; Mask to 32 bits
    or rdx, rax                             ; Combine with value
    
    ; Store to register based on index
    cmp cl, 0
    je store_r0
    cmp cl, 1
    je store_r1
    cmp cl, 2
    je store_r2
    cmp cl, 3
    je store_r3
    jmp interpreter_loop
    
store_r0:
    mov r8, rdx
    jmp interpreter_loop
store_r1:
    mov r9, rdx
    jmp interpreter_loop
store_r2:
    mov r10, rdx
    jmp interpreter_loop
store_r3:
    mov r11, rdx
    jmp interpreter_loop

; ---------------------------------------------------------------------------
; OP_RETURN (50h): Return value from register
; Format: OP_RETURN <src_reg>
; ---------------------------------------------------------------------------
op_return:
    ; Bounds check
    cmp rbx, r12
    jae error_truncated
    
    ; Read source register
    movzx rax, byte ptr [rbx]
    inc rbx
    
    ; Load value from register
    cmp al, 0
    je load_r0
    cmp al, 1
    je load_r1
    cmp al, 2
    je load_r2
    cmp al, 3
    je load_r3
    xor rax, rax
    jmp return_value
    
load_r0:
    mov rax, r8
    jmp return_value
load_r1:
    mov rax, r9
    jmp return_value
load_r2:
    mov rax, r10
    jmp return_value
load_r3:
    mov rax, r11
    jmp return_value

return_value:
    ; Store result
    mov rcx, [rsp + 48]
    mov [rcx], rax
    
    ; Update runtime arena bump
    mov [r15 + 8], r14
    
    ; Return success
    mov rax, 1
    jmp cleanup

; ---------------------------------------------------------------------------
; OP_LOAD_CONST (00h): Load constant from pool
; Format: OP_LOAD_CONST <const_idx> <dst_reg>
; For Milestone 1: skip operands
; ---------------------------------------------------------------------------
op_load_const:
    add rbx, 2
    jmp interpreter_loop

; ---------------------------------------------------------------------------
; Error Handlers
; ---------------------------------------------------------------------------
error_unknown_opcode:
    xor rax, rax
    jmp cleanup

error_truncated:
    xor rax, rax
    jmp cleanup

execution_complete:
    ; Reached end without return - return undefined
    mov rcx, [rsp + 48]
    mov rax, 07FF3000000000001h
    mov [rcx], rax
    mov rax, 1
    jmp cleanup

cleanup:
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
ExecuteBytecode_MASM ENDP

END
