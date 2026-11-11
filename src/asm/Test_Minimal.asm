; Minimal test - no macros
.data
ALIGN 16
TestData QWORD 0

.code

PUBLIC TestFunction

TestFunction PROC
    push rbx
    mov rax, 123
    mov QWORD PTR [TestData], rax
    pop rbx
    ret
TestFunction ENDP

END