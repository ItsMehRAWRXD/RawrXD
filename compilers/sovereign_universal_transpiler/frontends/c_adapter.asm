; c_adapter.asm - C frontend for Sovereign Universal Transpiler
; Target: printf("text");
; Generates: IR_LOAD_CONST + IR_CALL print + IR_EXIT

include uir.asm

.data
    kw_printf    db "printf", 0

.code

; CCompile - Compile C source to UIR
; RCX = source buffer
; RDX = source size
; R8  = UIR output buffer
; Returns: RAX = node count
CCompile PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h
    
    mov rsi, rcx            ; source
    mov rbx, rdx            ; source size
    mov rdi, r8             ; UIR buffer
    xor r10, r10            ; node count
    
    ; Skip whitespace and find "printf"
c_skip_ws:
    cmp rbx, 0
    jle c_error
    mov al, [rsi]
    cmp al, ' '
    je c_skip_one
    cmp al, 9               ; tab
    je c_skip_one
    cmp al, 10              ; LF
    je c_skip_one
    cmp al, 13              ; CR
    je c_skip_one
    jmp c_check_printf
c_skip_one:
    inc rsi
    dec rbx
    jmp c_skip_ws
    
c_check_printf:
    ; Check for "printf"
    cmp dword ptr [rsi], 69667270h     ; "prif" (little-endian "printf")
    jne c_error
    cmp word ptr [rsi + 4], 666Eh      ; "fn"
    jne c_error
    add rsi, 6
    sub rbx, 6
    
    ; Skip whitespace
c_skip_ws2:
    cmp rbx, 0
    jle c_error
    mov al, [rsi]
    cmp al, ' '
    je c_skip_one2
    jmp c_check_paren
c_skip_one2:
    inc rsi
    dec rbx
    jmp c_skip_ws2
    
c_check_paren:
    ; Expect opening paren
    mov al, [rsi]
    cmp al, '('
    jne c_error
    inc rsi
    dec rbx
    
    ; Skip whitespace
c_skip_ws3:
    mov al, [rsi]
    cmp al, ' '
    jne c_parse_string
    inc rsi
    dec rbx
    jmp c_skip_ws3
    
c_parse_string:
    ; Expect string literal
    mov al, [rsi]
    cmp al, '"'
    jne c_error
    inc rsi
    dec rbx
    mov rcx, rsi             ; save string start
    
c_str_loop:
    cmp rbx, 0
    jle c_error
    mov al, [rsi]
    cmp al, '"'
    je c_str_end
    cmp al, 0
    je c_error
    cmp al, 10               ; newline in string
    je c_error
    inc rsi
    dec rbx
    jmp c_str_loop
c_str_end:
    mov rax, rsi
    sub rax, rcx             ; string length
    mov r11, rax
    inc rsi                  ; skip closing quote
    dec rbx
    
    ; Skip whitespace
c_skip_ws4:
    mov al, [rsi]
    cmp al, ' '
    jne c_check_close
    inc rsi
    dec rbx
    jmp c_skip_ws4
    
c_check_close:
    ; Expect closing paren
    mov al, [rsi]
    cmp al, ')'
    jne c_error
    inc rsi
    dec rbx
    
    ; Optional semicolon
    cmp rbx, 0
    jle c_emit
    mov al, [rsi]
    cmp al, ';'
    jne c_emit
    inc rsi
    dec rbx
    
c_emit:
    ; Emit IR_LOAD_CONST
    mov dword ptr [rdi], IR_LOAD_CONST
    mov dword ptr [rdi + 4], 0
    mov [rdi + 8], rcx              ; string pointer
    mov [rdi + 16], r11             ; string length
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    ; Emit IR_CALL (print)
    mov dword ptr [rdi], IR_CALL
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 1      ; function ID = print
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    ; Emit IR_EXIT
    mov dword ptr [rdi], IR_EXIT
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 0
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    jmp c_done
    
c_error:
    xor r10, r10
    
c_done:
    mov rax, r10
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
CCompile ENDP

end