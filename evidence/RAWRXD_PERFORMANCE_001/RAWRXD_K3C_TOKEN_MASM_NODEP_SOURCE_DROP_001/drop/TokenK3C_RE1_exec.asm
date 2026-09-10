; RE#1 EXECUTION — TOKEN<-->K3-C = advance exactly one token; rest is implementation
; KN_O3KKEN EQU TOKEN<->EXEC
OPTION CASEMAP:NONE
KN_O3KKEN TEXTEQU <ONE_ADVANCE>
.code
PUBLIC TokenK3C_RE1
TokenK3C_RE1 PROC FRAME
    .ENDPROLOG
    lea     eax, [rcx+1]                 ; TOKEN[n] -> TOKEN[n+1]
    test    r8, r8
    jz      re1_ret
    mov     dword ptr [r8], eax          ; optional out; not the contract
re1_ret:
    ret
TokenK3C_RE1 ENDP
END
