; rag_gfx.asm - Ultra-low-latency direct GDI blitter
; (C) 2026 Sovereign Engine / RAGE-Inspired Core
; -----------------------------------------------------------------------------

.code

extern BitBlt : proc

PUBLIC XR_Gfx_Blit_Hardened
XR_Gfx_Blit_Hardened PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64                ; Calibrated 64-byte shadow+param space (Win64 ABI 16-byte aligned)
    
    ; Preservation
    push rsi
    push rdi
    
    ; Parameters arriving in:
    ; RCX = hdcDest
    ; RDX = xDest
    ; R8  = yDest
    ; R9  = width
    ; [RBP+48] = height (Stack Parameter 5)
    ; [RBP+56] = hdcSrc (Stack Parameter 6)
    
    ; Preservation of caller's stack param access if needed
    ; But we need to call BitBlt which has 9 args.
    
    ; BitBlt(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop)
    ; RCX, RDX, R8, R9 are already in place for 1, 2, 3, 4.
    
    ; 5. cy
    mov rax, [rbp+48]
    mov [rsp+32], rax
    
    ; 6. hdcSrc
    mov rax, [rbp+56]
    mov [rsp+40], rax
    
    ; 7. x1
    mov qword ptr [rsp+48], 0
    
    ; 8. y1
    mov qword ptr [rsp+56], 0
    
    ; 9. rop (SRCCOPY = 00CC0020h)
    mov qword ptr [rsp+64], 00CC0020h

    call BitBlt
    
    pop rdi
    pop rsi
    mov rsp, rbp
    pop rbp
    ret
XR_Gfx_Blit_Hardened ENDP

end