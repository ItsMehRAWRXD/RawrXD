; ==============================================================================
; SimpleRMSNorm.asm - Simple test version without parameters
; ==============================================================================

.code

SimpleRMSNorm PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Just return immediately
    mov     rsp, rbp
    pop     rbp
    ret
SimpleRMSNorm ENDP

END