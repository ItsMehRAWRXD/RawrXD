; rawr_product_x64.asm — ABI version, caps, token estimate, FNV-1a
OPTION CASEMAP:NONE
.code

PUBLIC RawrProductAbiVer
PUBLIC RawrProductCaps
PUBLIC RawrTokenEst
PUBLIC RawrFnv1a32

; eax = runtime ABI v1
RawrProductAbiVer PROC
    mov     eax, 1
    ret
RawrProductAbiVer ENDP

; eax = STREAM|TOOLS|SESSION|REPO|COMPLETE|AGENT (63)
RawrProductCaps PROC
    mov     eax, 63
    ret
RawrProductCaps ENDP

; ecx = char count → eax ≈ tokens (ceil n/4)
RawrTokenEst PROC
    mov     eax, ecx
    add     eax, 3
    shr     eax, 2
    ret
RawrTokenEst ENDP

; rcx = buf, edx = len → eax = FNV-1a 32
RawrFnv1a32 PROC
    mov     r8, rcx
    mov     eax, 2166136261
    test    edx, edx
    jz      fnv_done
    xor     ecx, ecx
fnv_lp:
    movzx   r9d, BYTE PTR [r8+rcx]
    xor     eax, r9d
    imul    eax, 16777619
    inc     ecx
    cmp     ecx, edx
    jb      fnv_lp
fnv_done:
    ret
RawrFnv1a32 ENDP

END
