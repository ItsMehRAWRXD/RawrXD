; Deep2R1_StrEq.asm — ASCII equality, no CRT
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc

PUBLIC StrEqA

.code
; RCX/RDX = zstrings. EAX=1 equal. Clobbers R10/R11.
StrEqA PROC
    test rcx, rcx
    jz short SEA_No
    test rdx, rdx
    jz short SEA_No
SEA_Loop:
    mov r10b, byte ptr [rcx]
    mov r11b, byte ptr [rdx]
    cmp r10b, r11b
    jne short SEA_No
    test r10b, r10b
    jz short SEA_Yes
    inc rcx
    inc rdx
    jmp short SEA_Loop
SEA_Yes:
    mov eax, 1
    ret
SEA_No:
    xor eax, eax
    ret
StrEqA ENDP
END
