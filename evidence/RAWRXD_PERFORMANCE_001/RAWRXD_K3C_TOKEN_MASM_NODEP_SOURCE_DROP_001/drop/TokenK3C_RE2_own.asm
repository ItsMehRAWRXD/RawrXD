; RE#2 OWNERSHIP — TOKEN owns nothing; K3-C owns all required for TOKEN[n]->TOKEN[n+1]
; KN_O3KKEN EQU INPUT=OUTPUT  (state is K3-C private; TOKEN never owns it)
OPTION CASEMAP:NONE
KN_O3KKEN TEXTEQU <ONE_BOUNDARY>
.code
PUBLIC TokenK3C_RE2
TokenK3C_RE2 PROC FRAME
    .ENDPROLOG
    ; RDX = K3-C private state (TOKEN has zero ownership obligation)
    test    rdx, rdx
    jz      re2_tok
    mov     dword ptr [rdx+4], ecx       ; K3-C-owned last
    mov     r10d, dword ptr [rdx]
    test    r10d, r10d
    jz      re2_tok
    dec     r10d
    mov     dword ptr [rdx], r10d        ; K3-C-owned remain
re2_tok:
    lea     eax, [rcx+1]                 ; only TOKEN transition is visible
    test    r8, r8
    jz      re2_ret
    mov     dword ptr [r8], eax
re2_ret:
    ret
TokenK3C_RE2 ENDP
END
