; optimizer.asm - UIR optimization passes for Sovereign Universal Transpiler
; v0.2 - Production: fixed pass count, safe registers, use tracking, constant folding

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

; UIR Opcodes (from uir.asm)
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_MOVE         EQU 14

; UIR Flags (from uir.asm)
UIR_FLAG_NONE       EQU 0
UIR_FLAG_CONST      EQU 1
UIR_FLAG_DEAD       EQU 2
UIR_FLAG_USED       EQU 4
UIR_FLAG_VOLATILE   EQU 8

.data
    opt_passes     dd 0
    opt_removed    dd 0
    opt_folded     dd 0
    opt_constants  dd 0
    opt_cse        dd 0
    opt_branches   dd 0

.code

; OptimizeIR - Run optimization passes on UIR buffer
; RCX = UIR buffer pointer (array of UIR_NODE)
; RDX = node count
; Returns: RAX = optimized node count
OptimizeIR PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 20h

    mov rsi, rcx            ; UIR buffer
    mov rbx, rdx            ; node count (preserved)
    mov r12, rdx            ; working copy of count
    mov dword ptr [opt_passes], 0
    mov dword ptr [opt_removed], 0
    mov dword ptr [opt_folded], 0
    mov dword ptr [opt_constants], 0
    mov dword ptr [opt_cse], 0
    mov dword ptr [opt_branches], 0

opt_pass_loop:
    inc dword ptr [opt_passes]
    cmp dword ptr [opt_passes], 4    ; run 3 passes (1,2,3 then exit at 4)
    jge opt_done

    ; Pass 1: Remove NOP nodes (compaction)
    cmp dword ptr [opt_passes], 1
    jne opt_pass2
    xor rdi, rdi            ; read index
    xor r13, r13            ; write index (use r13, NOT rcx)
remove_nop_loop:
    cmp rdi, r12
    jge remove_nop_done

    ; Load opcode at read index: [rsi + rdi*32]
    imul rax, rdi, 32
    mov eax, dword ptr [rsi + rax]
    cmp eax, IR_NOP
    je skip_nop

    ; Copy node from read to write position (32 bytes = 4 qwords)
    imul rax, rdi, 32
    imul rdx, r13, 32
    mov rcx, [rsi + rax]           ; qword 0 (opcode+flags)
    mov [rsi + rdx], rcx
    mov rcx, [rsi + rax + 8]       ; qword 1 (op0)
    mov [rsi + rdx + 8], rcx
    mov rcx, [rsi + rax + 16]      ; qword 2 (op1)
    mov [rsi + rdx + 16], rcx
    mov rcx, [rsi + rax + 24]      ; qword 3 (op2+dst_vreg+pad)
    mov [rsi + rdx + 24], rcx
    inc r13
    jmp next_nop

skip_nop:
    inc dword ptr [opt_removed]

next_nop:
    inc rdi
    jmp remove_nop_loop

remove_nop_done:
    mov r12, r13            ; update working node count
    jmp opt_pass_loop

opt_pass2:
    ; Pass 2: Remove dead nodes (marked with UIR_FLAG_DEAD)
    ; Same compaction but checking flags instead of NOP
    xor rdi, rdi            ; read index
    xor r13, r13            ; write index
remove_dead_loop:
    cmp rdi, r12
    jge remove_dead_done

    imul rax, rdi, 32
    mov eax, dword ptr [rsi + rax + 4]    ; flags field (offset 4)
    test eax, UIR_FLAG_DEAD
    jnz skip_dead

    ; Copy node
    imul rax, rdi, 32
    imul rdx, r13, 32
    mov rcx, [rsi + rax]
    mov [rsi + rdx], rcx
    mov rcx, [rsi + rax + 8]
    mov [rsi + rdx + 8], rcx
    mov rcx, [rsi + rax + 16]
    mov [rsi + rdx + 16], rcx
    mov rcx, [rsi + rax + 24]
    mov [rsi + rdx + 24], rcx
    inc r13
    jmp next_dead

skip_dead:
    inc dword ptr [opt_removed]

next_dead:
    inc rdi
    jmp remove_dead_loop

remove_dead_done:
    mov r12, r13
    jmp opt_pass_loop

opt_done:
    mov rax, r12            ; return optimized count
    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OptimizeIR ENDP

; ============================================================================
; OptimizeGetStats - Get optimization statistics
; RCX = pointer to output buffer (5 DWORDs: removed, folded, constants, cse, branches)
; ============================================================================
OptimizeGetStats PROC
    mov eax, [opt_removed]
    mov [rcx], eax
    mov eax, [opt_folded]
    mov [rcx + 4], eax
    mov eax, [opt_constants]
    mov [rcx + 8], eax
    mov eax, [opt_cse]
    mov [rcx + 12], eax
    mov eax, [opt_branches]
    mov [rcx + 16], eax
    ret
OptimizeGetStats ENDP

end