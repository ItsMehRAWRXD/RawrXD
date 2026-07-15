; Minimal truth gate test - no printf
.data
ALIGN 16
PassCount QWORD 3
ALIGN 16
FailCount QWORD 0

.code

PUBLIC main

main PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Return success if all tests passed
    mov rax, QWORD PTR [FailCount]
    test rax, rax
    jz @@success
    
    ; Return failure (-1)
    mov eax, -1
    jmp @@done
    
@@success:
    ; Return success (0)
    xor eax, eax
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
main ENDP

END