; rawr_product_pipe_x64.asm — little-endian u32 frame length
OPTION CASEMAP:NONE
.code

PUBLIC RawrStoreU32
PUBLIC RawrLoadU32

; rcx = dst, edx = value
RawrStoreU32 PROC
    mov     DWORD PTR [rcx], edx
    ret
RawrStoreU32 ENDP

; rcx = src → eax
RawrLoadU32 PROC
    mov     eax, DWORD PTR [rcx]
    ret
RawrLoadU32 ENDP

END
