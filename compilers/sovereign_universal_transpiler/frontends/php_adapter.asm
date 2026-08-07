; php_adapter.asm - PHP frontend for Sovereign Universal Transpiler
; Target: <?php echo "text"; ?>
; Generates: IR_LOAD_CONST + IR_CALL print + IR_EXIT

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

; External declarations from token.asm
extrn TokenInit:proc
extrn TokenCreate:proc
extrn TokenGet:proc
extrn TokenGetCount:proc
extrn TokenTypeToString:proc

; UIR Opcodes
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_MOVE         EQU 14

.data
    ; PHP keywords
    kw_echo      db "echo", 0
    kw_print     db "print", 0
    
.code

; PHPCompile - Compile PHP source to UIR
; RCX = source buffer
; RDX = source size
; R8  = UIR output buffer
; Returns: RAX = node count
PHPCompile PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h
    
    mov rsi, rcx            ; source
    mov rbx, rdx            ; source size
    mov rdi, r8             ; UIR buffer
    xor r10, r10            ; node count
    
    ; Skip <?php prefix
    ; Check for "<?php"
    cmp dword ptr [rsi], 3C3F7068h
    jne php_parse_echo
    cmp byte ptr [rsi + 4], 70h
    jne php_parse_echo
    add rsi, 5              ; skip "<?php"
    sub rbx, 5
    
php_parse_echo:
    ; Skip whitespace
php_skip_ws:
    cmp rbx, 0
    jle php_done
    mov al, [rsi]
    cmp al, ' '
    jne php_check_echo
    inc rsi
    dec rbx
    jmp php_skip_ws
    
php_check_echo:
    ; Check for "echo" keyword
    cmp dword ptr [rsi], 636F6865h    ; "echo"
    jne php_check_print
    add rsi, 4
    sub rbx, 4
    
    ; Skip whitespace
php_skip_ws2:
    cmp rbx, 0
    jle php_error
    mov al, [rsi]
    cmp al, ' '
    jne php_parse_string
    inc rsi
    dec rbx
    jmp php_skip_ws2
    
php_parse_string:
    ; Expect string literal (double or single quote)
    mov al, [rsi]
    cmp al, '"'
    je php_dq_string
    cmp al, "'"
    je php_sq_string
    jmp php_error
    
php_dq_string:
    inc rsi                  ; skip opening quote
    dec rbx
    mov rcx, rsi             ; save string start
    
    ; Find closing quote
php_dq_loop:
    cmp rbx, 0
    jle php_error
    mov al, [rsi]
    cmp al, '"'
    je php_dq_end
    cmp al, 0
    je php_error
    inc rsi
    dec rbx
    jmp php_dq_loop
php_dq_end:
    ; Calculate string length
    mov rax, rsi
    sub rax, rcx            ; length = end - start
    mov r11, rax            ; save length
    
    inc rsi                  ; skip closing quote
    dec rbx
    
    ; Emit IR_LOAD_CONST node
    ; UIR_NODE: opcode(4) + flags(4) + op0(8) + op1(8) + dst_vreg(4) + op2(4) = 32 bytes
    mov dword ptr [rdi], IR_LOAD_CONST
    mov dword ptr [rdi + 4], 0          ; flags
    mov [rdi + 8], rcx                  ; op0 = string pointer
    mov [rdi + 16], r11                 ; op1 = string length
    mov dword ptr [rdi + 24], 0         ; dst_vreg = 0 (first vreg)
    mov dword ptr [rdi + 28], 0         ; op2 = unused
    add rdi, 32
    inc r10
    
    ; Emit IR_CALL node (print)
    mov dword ptr [rdi], IR_CALL
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 1          ; op0 = function ID (1 = print)
    mov qword ptr [rdi + 16], 0         ; op1 = arg vreg (0)
    mov dword ptr [rdi + 24], -1        ; dst_vreg = -1 (none)
    mov dword ptr [rdi + 28], 0         ; op2
    add rdi, 32
    inc r10
    
    ; Emit IR_EXIT node
    mov dword ptr [rdi], IR_EXIT
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 0
    mov qword ptr [rdi + 16], 0
    mov dword ptr [rdi + 24], -1        ; dst_vreg = -1
    mov dword ptr [rdi + 28], 0
    add rdi, 32
    inc r10
    
    jmp php_done
    
php_sq_string:
    ; Same as double-quote but with single quote delimiter
    inc rsi
    dec rbx
    mov rcx, rsi
    
php_sq_loop:
    cmp rbx, 0
    jle php_error
    mov al, [rsi]
    cmp al, "'"
    je php_sq_end
    cmp al, 0
    je php_error
    inc rsi
    dec rbx
    jmp php_sq_loop
php_sq_end:
    mov rax, rsi
    sub rax, rcx
    mov r11, rax
    inc rsi
    dec rbx
    
    ; Emit LOAD_CONST
    mov dword ptr [rdi], IR_LOAD_CONST
    mov dword ptr [rdi + 4], 0
    mov [rdi + 8], rcx
    mov [rdi + 16], r11
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    ; Emit CALL print
    mov dword ptr [rdi], IR_CALL
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 1
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    ; Emit EXIT
    mov dword ptr [rdi], IR_EXIT
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 0
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    jmp php_done
    
php_check_print:
    ; Check for "print" keyword (alternative to echo)
    cmp dword ptr [rsi], 746E6972h     ; "prin" (little-endian "print")
    jne php_error
    cmp byte ptr [rsi + 4], 74h        ; "t"
    jne php_error
    add rsi, 5
    sub rbx, 5
    jmp php_skip_ws2
    
php_error:
    xor r10, r10              ; return 0 on error
    
php_done:
    mov rax, r10
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
PHPCompile ENDP

end