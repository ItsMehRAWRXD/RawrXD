option casemap:none
include ss_real_provider.inc

.data
anchor_primary   db "token_embd.weight",0
anchor_fallback  db "output.weight",0

.code

; Adapter-only tensor vocabulary. Residency/provider/device core remains family-neutral.
ss_find_anchor_tensor PROC
    test rcx,rcx
    jz sfa_bad
    test rdx,rdx
    jz sfa_bad
    mov r9,rdx
    lea rdx,anchor_primary
    lea r8,anchor_fallback
    jmp ss_gguf_find_tensor2
sfa_bad:
    mov eax,SS_E_INVALID
    ret
ss_find_anchor_tensor ENDP

END
