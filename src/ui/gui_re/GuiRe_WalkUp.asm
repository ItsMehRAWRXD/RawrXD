; GuiRe_WalkUp.asm — leaf → parent chain → root (end-side-out)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN g_guiReWalkBuf:QWORD
EXTRN g_guiReHdr:BYTE
EXTRN g_guiReCount:DWORD
EXTRN GuiRe_CaptureHwnd:PROC

PUBLIC GuiRe_WalkUp
PUBLIC GuiRe_Reset

.CODE

GuiRe_Reset PROC
    mov     g_guiReCount, 0
    lea     rax, g_guiReHdr
    mov     dword ptr [rax].GUIRE_HDR.magic, 'RiGu'  ; 'GuIR' LE
    mov     dword ptr [rax].GUIRE_HDR.version, 1
    mov     dword ptr [rax].GUIRE_HDR.count, 0
    mov     qword ptr [rax].GUIRE_HDR.rootHwnd, 0
    mov     qword ptr [rax].GUIRE_HDR.leafHwnd, 0
    xor     eax, eax
    ret
GuiRe_Reset ENDP

; RCX = leaf HWND
; Walks GetParent until null; captures each node depth 0..n (leaf first).
; RAX = nodes captured
GuiRe_WalkUp PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40h
    .allocstack 40h
    .endprolog

    mov     rbx, rcx                 ; current
    call    GuiRe_Reset
    lea     rax, g_guiReHdr
    mov     [rax].GUIRE_HDR.leafHwnd, rbx

    xor     esi, esi                 ; depth / walk index
walk:
    test    rbx, rbx
    jz      fin
    cmp     esi, GUIRE_MAX_NODES
    jae     fin

    lea     rdi, g_guiReWalkBuf
    mov     [rdi + rsi*8], rbx

    mov     rcx, rbx
    mov     edx, esi
    call    GuiRe_CaptureHwnd

    mov     rcx, rbx
    call    GetParent
    mov     rbx, rax
    inc     esi
    jmp     walk

fin:
    lea     rax, g_guiReHdr
    mov     ecx, g_guiReCount
    mov     [rax].GUIRE_HDR.count, ecx
    test    esi, esi
    jz      @f
    lea     rdi, g_guiReWalkBuf
    mov     rdx, [rdi + rsi*8 - 8]   ; last = rootward
    mov     [rax].GUIRE_HDR.rootHwnd, rdx
@@:
    mov     eax, g_guiReCount
    add     rsp, 40h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiRe_WalkUp ENDP

END
