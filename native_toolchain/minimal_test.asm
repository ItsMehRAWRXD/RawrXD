; Minimal test for native assembler
; This uses only instructions the native assembler understands

.CODE
Start:
    xor rax, rax
    mov rcx, 5
    add rax, rcx
    sub rax, 2
    push rax
    pop rbx
    cmp rax, rbx
    je label1
    nop
label1:
    call ExitProcess

ExitProcess:
    ret

END
