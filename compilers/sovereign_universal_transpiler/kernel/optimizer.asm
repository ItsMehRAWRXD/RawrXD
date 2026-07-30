; optimizer.asm - UIR optimization passes for Sovereign Universal Transpiler
; v0.1: constant folding + dead node removal

include uir.asm

.data
    opt_passes     dd 0
    opt_removed    dd 0
    opt_folded     dd 0

.code

; OptimizeIR - Run optimization passes on UIR buffer
; RCX = UIR buffer pointer
; RDX = node count
; Returns: RAX = optimized node count
OptimizeIR PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h
    
    mov rsi, rcx            ; UIR buffer
    mov rbx, rdx            ; node count
    mov dword ptr [opt_passes], 0
    mov dword ptr [opt_removed], 0
    mov dword ptr [opt_folded], 0
    
opt_pass_loop:
    inc dword ptr [opt_passes]
    cmp dword ptr [opt_passes], 3    ; max 3 passes
    jge opt_done
    
    ; Pass 1: Remove NOP nodes
    xor rdi, rdi            ; read index
    xor rcx, rcx            ; write index
remove_nop_loop:
    cmp rdi, rbx
    jge remove_nop_done
    
    ; Load node at read index
    mov eax, [rsi + rdi * 32]        ; opcode (offset 0, 4 bytes + padding)
    ; UIR_NODE is 32 bytes: opcode(4) + flags(4) + op0(8) + op1(8) + op2(8)
    cmp eax, IR_NOP
    je skip_nop
    
    ; Copy node from read to write position
    ; Copy 32 bytes
    mov rax, [rsi + rdi * 32]        ; qword 0 (opcode+flags)
    mov [rsi + rcx * 32], rax
    mov rax, [rsi + rdi * 32 + 8]    ; qword 1 (op0)
    mov [rsi + rcx * 32 + 8], rax
    mov rax, [rsi + rdi * 32 + 16]   ; qword 2 (op1)
    mov [rsi + rcx * 32 + 16], rax
    mov rax, [rsi + rdi * 32 + 24]   ; qword 3 (op2)
    mov [rsi + rcx * 32 + 24], rax
    inc rcx
    jmp next_nop
    
skip_nop:
    inc dword ptr [opt_removed]
    
next_nop:
    inc rdi
    jmp remove_nop_loop
    
remove_nop_done:
    mov rbx, rcx            ; update node count
    
    ; Pass 2: Constant folding (placeholder for v0.2)
    ; For now, just count potential folds
    ; Real implementation would detect:
    ;   LOAD_CONST + LOAD_CONST + ADD -> LOAD_CONST (result)
    
opt_done:
    mov rax, rbx            ; return optimized count
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
OptimizeIR ENDP

end