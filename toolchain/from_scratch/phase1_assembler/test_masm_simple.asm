; Test MASM file for preprocessor
; Tests: EQU, INCLUDE (simulated), basic syntax

NULL EQU 0
TRUE EQU 1
FALSE EQU 0

.DATA

msg db "Hello", 0
value dd 0x12345678

.CODE

main PROC
    xor eax, eax
    mov eax, TRUE
    cmp eax, NULL
    jne done
    
done:
    xor ecx, ecx
    ret

main ENDP

END
