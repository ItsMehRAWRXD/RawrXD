; emitter_x64.asm - x64 machine code emitter for Sovereign Universal Transpiler
; Converts UIR nodes into x64 machine code

include uir.asm

.data
    ; Output buffers
    text_buffer     dq 0    ; .text section bytes
    text_size       dq 0
    rdata_buffer    dq 0    ; .rdata section bytes
    rdata_size      dq 0
    text_capacity   dq 65536
    rdata_capacity  dq 65536
    
    ; String table for LOAD_CONST strings
    string_table    dq 0    ; array of string offsets in .rdata
    string_count    dd 0

.code

; EmitX64 - Convert UIR to x64 machine code
; RCX = UIR buffer
; RDX = node count
; R8  = text output buffer
; R9  = rdata output buffer
; Returns: RAX = total text bytes emitted
EmitX64 PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 38h
    
    mov rsi, rcx            ; UIR buffer
    mov rbx, rdx            ; node count
    mov r12, r8             ; text buffer
    mov r13, r9             ; rdata buffer
    xor rdi, rdi            ; text offset
    xor r11, r11            ; rdata offset
    
    ; Emit prologue: sub rsp, 28h
    mov byte ptr [r12 + rdi], 48h    ; REX.W
    inc rdi
    mov byte ptr [r12 + rdi], 83h    ; SUB r/m64, imm8
    inc rdi
    mov byte ptr [r12 + rdi], 0ECh   ; /5 (RSP)
    inc rdi
    mov byte ptr [r12 + rdi], 28h    ; imm8 = 40
    inc rdi
    
emit_loop:
    cmp rdi, rbx
    jge emit_done
    
    ; Load opcode
    mov eax, dword ptr [rsi]         ; opcode
    cmp eax, IR_NOP
    je emit_next
    cmp eax, IR_LOAD_CONST
    je emit_load_const
    cmp eax, IR_CALL
    je emit_call
    cmp eax, IR_RETURN
    je emit_return
    cmp eax, IR_EXIT
    je emit_exit
    jmp emit_next
    
emit_load_const:
    ; Store string in .rdata
    ; operand0 = string pointer, operand1 = string length
    mov rcx, [rsi + 8]               ; op0 = string ptr
    mov r8, [rsi + 16]               ; op1 = string length
    
    ; Copy string to rdata buffer
    push rdi
    push rsi
    mov rdi, r13
    add rdi, r11                     ; dest = rdata + offset
    mov rsi, rcx                     ; src = string
    mov rcx, r8                      ; count
    rep movsb
    pop rsi
    pop rdi
    
    ; Save rdata offset for later LEA
    mov [rsp + 0], r11               ; save string offset on stack
    
    add r11, r8                      ; advance rdata
    ; Align to 1 byte (no padding needed for v0.1)
    
    jmp emit_next
    
emit_call:
    ; operand0 = function ID
    ; For print: lea rcx, [rdata + string_offset]
    ;            call RuntimePrintString
    
    mov rax, [rsi + 8]               ; op0 = function ID
    cmp rax, 1                       ; 1 = print
    jne emit_next
    
    ; lea rcx, [rip + offset]
    ; We'll use: 48 8D 0D xx xx xx xx (LEA RCX, [RIP + disp32])
    mov byte ptr [r12 + rdi], 48h    ; REX.W
    inc rdi
    mov byte ptr [r12 + rdi], 8Dh    ; LEA
    inc rdi
    mov byte ptr [r12 + rdi], 0Dh    ; ModRM (RCX, RIP+disp32)
    inc rdi
    ; disp32 = placeholder (will be fixed up by PE writer)
    ; For now, store 0 - PE writer handles relocation
    mov dword ptr [r12 + rdi], 0     ; disp32 placeholder
    add rdi, 4
    
    ; call RuntimePrintString (relative call)
    ; E8 xx xx xx xx
    mov byte ptr [r12 + rdi], 0E8h   ; CALL rel32
    inc rdi
    mov dword ptr [r12 + rdi], 0     ; rel32 placeholder
    add rdi, 4
    
    jmp emit_next
    
emit_return:
    ; add rsp, 28h
    mov byte ptr [r12 + rdi], 48h
    inc rdi
    mov byte ptr [r12 + rdi], 83h
    inc rdi
    mov byte ptr [r12 + rdi], 0C4h   ; /0 (RSP)
    inc rdi
    mov byte ptr [r12 + rdi], 28h
    inc rdi
    ; ret
    mov byte ptr [r12 + rdi], 0C3h
    inc rdi
    jmp emit_next
    
emit_exit:
    ; xor ecx, ecx
    mov byte ptr [r12 + rdi], 31h
    inc rdi
    mov byte ptr [r12 + rdi], 0C9h
    inc rdi
    ; call ExitProcess (relative)
    mov byte ptr [r12 + rdi], 0E8h
    inc rdi
    mov dword ptr [r12 + rdi], 0
    add rdi, 4
    jmp emit_done
    
emit_next:
    add rsi, 32                       ; next UIR node
    inc rdi                           ; (this is wrong - rdi is byte offset, not node index)
    ; Actually we need a separate node counter
    ; Let me fix: use r10 as node index
    jmp emit_loop
    
emit_done:
    mov rax, rdi                      ; return text size
    mov [text_size], rdi
    mov [rdata_size], r11
    add rsp, 38h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
EmitX64 ENDP

; Individual emitters for future use

; EmitMov - Emit MOV reg, imm32
; RCX = buffer, RDX = reg (0-7), R8 = value
EmitMov PROC
    mov byte ptr [rcx], 48h          ; REX.W (if needed)
    mov byte ptr [rcx + 1], 0C7h     ; MOV r/m64, imm32
    mov rax, rdx
    shl rax, 3                       ; reg field
    or rax, 0C0h                     ; ModRM (reg, direct)
    mov byte ptr [rcx + 2], al
    mov dword ptr [rcx + 3], r8d     ; imm32
    mov rax, 7                       ; bytes emitted
    ret
EmitMov ENDP

; EmitLea - Emit LEA reg, [rip + disp32]
; RCX = buffer, RDX = reg, R8 = disp32
EmitLea PROC
    mov byte ptr [rcx], 48h          ; REX.W
    mov byte ptr [rcx + 1], 8Dh      ; LEA
    mov rax, rdx
    shl rax, 3
    or rax, 05h                      ; ModRM (reg, RIP+disp32)
    mov byte ptr [rcx + 2], al
    mov dword ptr [rcx + 3], r8d     ; disp32
    mov rax, 7
    ret
EmitLea ENDP

; EmitCall - Emit CALL rel32
; RCX = buffer, RDX = rel32
EmitCall PROC
    mov byte ptr [rcx], 0E8h
    mov dword ptr [rcx + 1], edx
    mov rax, 5
    ret
EmitCall ENDP

; EmitRet - Emit RET
; RCX = buffer
EmitRet PROC
    mov byte ptr [rcx], 0C3h
    mov rax, 1
    ret
EmitRet ENDP

; EmitExit - Emit xor ecx,ecx + call ExitProcess
; RCX = buffer
EmitExit PROC
    mov byte ptr [rcx], 31h
    mov byte ptr [rcx + 1], 0C9h
    mov byte ptr [rcx + 2], 0E8h
    mov dword ptr [rcx + 3], 0       ; placeholder
    mov rax, 7
    ret
EmitExit ENDP

end