; Deep2OuterStr.asm — zero-terminated ASCII helpers, no CRT
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
PUBLIC OuterLenA
PUBLIC OuterCopyZ
PUBLIC OuterCatZ
PUBLIC OuterZero

.code
; RCX=s  EAX=length
OuterLenA PROC
    xor eax, eax
    test rcx, rcx
    jz short OL_Done
OL_Loop:
    cmp byte ptr [rcx + rax], 0
    je short OL_Done
    inc eax
    jmp short OL_Loop
OL_Done:
    ret
OuterLenA ENDP

; RCX=dst RDX=src  EAX=copied chars excluding NUL
OuterCopyZ PROC
    xor eax, eax
    test rcx, rcx
    jz short OC_Done
    test rdx, rdx
    jz short OC_Nul
OC_Loop:
    mov r8b, byte ptr [rdx + rax]
    mov byte ptr [rcx + rax], r8b
    test r8b, r8b
    jz short OC_Done
    inc eax
    jmp short OC_Loop
OC_Nul:
    mov byte ptr [rcx], 0
OC_Done:
    ret
OuterCopyZ ENDP

; RCX=dst RDX=suffix
OuterCatZ PROC
    push rbx
    mov rbx, rcx
    call OuterLenA
    add rcx, rax
    call OuterCopyZ
    pop rbx
    ret
OuterCatZ ENDP

; RCX=dst EDX=bytes
OuterZero PROC
    test rcx, rcx
    jz short OZ_Done
    xor eax, eax
OZ_Loop:
    test edx, edx
    jz short OZ_Done
    mov byte ptr [rcx], 0
    inc rcx
    dec edx
    jmp short OZ_Loop
OZ_Done:
    ret
OuterZero ENDP
END
