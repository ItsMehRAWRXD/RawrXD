; python_adapter.asm - Python frontend for Sovereign Universal Transpiler
; Target: print("text")
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

; UIR Opcodes
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_MOVE         EQU 14

.code

; PythonCompile - Compile Python source to UIR
; RCX = source buffer
; RDX = source size
; R8  = UIR output buffer
; Returns: RAX = node count
PythonCompile PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 28h
    
    mov rsi, rcx            ; source
    mov rbx, rdx            ; source size
    mov rdi, r8             ; UIR buffer
    xor r10, r10            ; node count
    
    ; Skip whitespace
py_skip_ws:
    cmp rbx, 0
    jle py_error
    mov al, [rsi]
    cmp al, ' '
    je py_skip_one
    cmp al, 9
    je py_skip_one
    cmp al, 10
    je py_skip_one
    cmp al, 13
    je py_skip_one
    jmp py_check_print
py_skip_one:
    inc rsi
    dec rbx
    jmp py_skip_ws
    
py_check_print:
    ; Check for "print"
    cmp dword ptr [rsi], 69727070h     ; "prin" (LE)
    jne py_error
    cmp byte ptr [rsi + 4], 74h        ; "t"
    jne py_error
    add rsi, 5
    sub rbx, 5
    
    ; Skip whitespace
py_skip_ws2:
    cmp rbx, 0
    jle py_error
    mov al, [rsi]
    cmp al, ' '
    je py_skip_one2
    jmp py_check_paren
py_skip_one2:
    inc rsi
    dec rbx
    jmp py_skip_ws2
    
py_check_paren:
    ; Expect opening paren
    mov al, [rsi]
    cmp al, '('
    jne py_error
    inc rsi
    dec rbx
    
    ; Skip whitespace
py_skip_ws3:
    mov al, [rsi]
    cmp al, ' '
    jne py_parse_string
    inc rsi
    dec rbx
    jmp py_skip_ws3
    
py_parse_string:
    ; Expect string literal (double or single quote)
    mov al, [rsi]
    cmp al, '"'
    je py_dq_string
    cmp al, "'"
    je py_sq_string
    jmp py_error
    
py_dq_string:
    inc rsi
    dec rbx
    mov rcx, rsi
    
py_dq_loop:
    cmp rbx, 0
    jle py_error
    mov al, [rsi]
    cmp al, '"'
    je py_str_end
    cmp al, 0
    je py_error
    inc rsi
    dec rbx
    jmp py_dq_loop
    
py_sq_string:
    inc rsi
    dec rbx
    mov rcx, rsi
    
py_sq_loop:
    cmp rbx, 0
    jle py_error
    mov al, [rsi]
    cmp al, "'"
    je py_str_end
    cmp al, 0
    je py_error
    inc rsi
    dec rbx
    jmp py_sq_loop
    
py_str_end:
    mov rax, rsi
    sub rax, rcx            ; string length
    mov r11, rax
    inc rsi                  ; skip closing quote
    dec rbx
    
    ; Skip whitespace
py_skip_ws4:
    mov al, [rsi]
    cmp al, ' '
    jne py_check_close
    inc rsi
    dec rbx
    jmp py_skip_ws4
    
py_check_close:
    ; Expect closing paren
    mov al, [rsi]
    cmp al, ')'
    jne py_error
    inc rsi
    dec rbx
    
    ; Emit IR_LOAD_CONST
    mov dword ptr [rdi], IR_LOAD_CONST
    mov dword ptr [rdi + 4], 0
    mov [rdi + 8], rcx
    mov [rdi + 16], r11
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    inc r10
    
    ; Emit IR_CALL (print)
    mov dword ptr [rdi], IR_CALL
    mov dword ptr [rdi + 4], 0
    mov qword ptr [rdi + 8], 1
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
    
    jmp py_done
    
py_error:
    xor r10, r10
    
py_done:
    mov rax, r10
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
PythonCompile ENDP

end