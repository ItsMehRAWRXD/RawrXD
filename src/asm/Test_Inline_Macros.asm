; Test with inline macros
.data
ALIGN 16
TestData QWORD 0

.code

PUBLIC TestFunctionInline

TestFunctionInline PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    mov rax, 123
    mov QWORD PTR [TestData], rax
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
TestFunctionInline ENDP

END