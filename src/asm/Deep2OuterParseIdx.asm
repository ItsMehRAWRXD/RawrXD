; Deep2OuterParseIdx.asm — digits left of -of- are the shard index
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
PUBLIC Deep2Outer_ParseIndexLeft

.code
; RCX -> '-' of -of-   RDX=*index  EAX=1
Deep2Outer_ParseIndexLeft PROC
    push rsi
    mov rsi, rcx
    lea r10, [rsi-1]
P_Back:
    mov al, byte ptr [r10]
    cmp al, '0'
    jb P_Start
    cmp al, '9'
    ja P_Start
    dec r10
    jmp P_Back
P_Start:
    cmp byte ptr [r10], '-'
    jne P_No
    inc r10
    xor eax, eax
    xor r11d, r11d
P_Idx:
    cmp r10, rsi
    jae P_End
    movzx ecx, byte ptr [r10]
    cmp cl, '0'
    jb P_No
    cmp cl, '9'
    ja P_No
    imul eax, eax, 10
    sub ecx, '0'
    add eax, ecx
    inc r10
    inc r11d
    jmp P_Idx
P_End:
    test r11d, r11d
    jz P_No
    test eax, eax
    jz P_No
    mov dword ptr [rdx], eax
    mov eax, 1
    pop rsi
    ret
P_No:
    xor eax, eax
    pop rsi
    ret
Deep2Outer_ParseIndexLeft ENDP
END
