; RE#3 ELIMINATION — no model/loader/cache/residency/layer/GPU/storage contract
; KN_O3KKEN = TOKEN->TOKEN = .
OPTION CASEMAP:NONE
KN_O3KKEN TEXTEQU <TOKEN->TOKEN>
.code
PUBLIC TokenK3C_RE3
TokenK3C_RE3 PROC FRAME
    .ENDPROLOG
    lea     eax, [rcx+1]                 ; TOKEN -> TOKEN · ZERO DEPENDENCIES
    ret
TokenK3C_RE3 ENDP
END
