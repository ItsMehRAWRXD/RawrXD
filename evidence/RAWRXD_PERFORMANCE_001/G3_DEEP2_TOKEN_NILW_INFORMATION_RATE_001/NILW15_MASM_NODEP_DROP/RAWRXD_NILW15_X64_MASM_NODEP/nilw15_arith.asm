option casemap:none
include nilw15.inc

.code

; rcx=num, rdx=scale, r8=den → rax = num*scale/den; CF=1 on fail
Nilw15MulDiv PROC FRAME
    .endprolog
    test r8, r8
    jz md_fail
    mov rax, rdx
    mul rcx
    cmp rdx, r8
    jae md_fail
    div r8
    clc
    ret
md_fail:
    xor eax, eax
    stc
    ret
Nilw15MulDiv ENDP

END
