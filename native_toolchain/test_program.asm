; Test program for native toolchain
; This should compile and run

.code
start:
    ; Simple program: mov rax, 42; ret
    mov rax, rcx      ; 48 89 C8
    add rax, rdx      ; 48 01 D0
    ret               ; C3
end
