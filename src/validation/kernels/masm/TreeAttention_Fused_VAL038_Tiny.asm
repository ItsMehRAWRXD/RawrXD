; ═══════════════════════════════════════════════════════════════════════════════
; VAL-038: TINY VERSION - Just return immediately
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

PUBLIC TreeAttention_Fused_VAL038

.code

TreeAttention_Fused_VAL038 PROC
    ; Store marker and return immediately
    mov     dword ptr [rcx], 0AAAAAAAAh
    ret
TreeAttention_Fused_VAL038 ENDP

END
