option casemap:none
PUBLIC Deep2ActivationSwap
.code
; rcx=&ping, rdx=&pong. Pure handle/address swap; copies no activation bytes.
Deep2ActivationSwap PROC
    test rcx, rcx
    jz aps_fail
    test rdx, rdx
    jz aps_fail
    mov rax, [rcx]
    mov r8, [rdx]
    mov [rcx], r8
    mov [rdx], rax
    mov eax, 1
    ret
aps_fail:
    xor eax, eax
    ret
Deep2ActivationSwap ENDP
END
