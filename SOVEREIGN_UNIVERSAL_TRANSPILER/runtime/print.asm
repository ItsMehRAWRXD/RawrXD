; print.asm - Runtime print helper
; Provides native console output without CRT

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
.code

; RuntimePrintString - Print null-terminated string to console
; RCX = string pointer
; Returns: RAX = bytes written
RuntimePrintString PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 40h
    
    mov rsi, rcx            ; Save string pointer
    
    ; Get stdout handle (cache it)
    mov rax, hStdOut
    test rax, rax
    jnz have_handle
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
have_handle:
    ; Calculate string length
    mov rdi, rsi
    xor ecx, ecx
    dec rcx                 ; Max length
    xor eax, eax
    repne scasb
    not rcx
    dec rcx                 ; Actual length
    
    ; Write to console
    mov r8, rcx             ; Length
    mov rcx, hStdOut        ; Handle
    mov rdx, rsi            ; Buffer
    lea r9, bytes_written   ; Bytes written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rax, bytes_written
    
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    ret
RuntimePrintString ENDP

; RuntimePrintStringN - Print string with known length
; RCX = string pointer
; RDX = string length
RuntimePrintStringN PROC
    push rbx
    sub rsp, 40h
    
    mov rbx, rdx            ; Save length
    
    ; Get stdout handle
    mov rax, hStdOut
    test rax, rax
    jnz have_handle2
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
have_handle2:
    ; Write to console
    mov r8, rbx             ; Length
    mov rdx, rcx            ; Buffer
    mov rcx, hStdOut        ; Handle
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rax, bytes_written
    
    add rsp, 40h
    pop rbx
    ret
RuntimePrintStringN ENDP

; RuntimePrintNewline - Print CRLF
RuntimePrintNewline PROC
    push rbx
    sub rsp, 40h
    
    mov byte ptr [rsp+20h], 13  ; CR
    mov byte ptr [rsp+21h], 10  ; LF
    
    mov rax, hStdOut
    test rax, rax
    jnz have_handle3
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
have_handle3:
    lea rdx, [rsp+20h]
    mov r8, 2
    mov rcx, hStdOut
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    pop rbx
    ret
RuntimePrintNewline ENDP

END
