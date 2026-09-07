; Deep2R1_IsArch.asm — general.architecture matcher
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
EXTERN StrEqA:PROC
PUBLIC Deep2R1_IsArchitecture

.data
s_arch_deepseek2    db "deepseek2",0
s_arch_deepseek     db "deepseek",0
s_arch_deepseek_r1  db "deepseek-r1",0

.code
Deep2R1_IsArchitecture PROC PUBLIC
    sub rsp, 28h
    mov r8, rcx
    mov rcx, r8
    lea rdx, s_arch_deepseek2
    call StrEqA
    test eax, eax
    jnz short R1A_Done
    mov rcx, r8
    lea rdx, s_arch_deepseek
    call StrEqA
    test eax, eax
    jnz short R1A_Done
    mov rcx, r8
    lea rdx, s_arch_deepseek_r1
    call StrEqA
R1A_Done:
    add rsp, 28h
    ret
Deep2R1_IsArchitecture ENDP
END
