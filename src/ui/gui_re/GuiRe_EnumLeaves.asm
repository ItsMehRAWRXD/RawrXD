; GuiRe_EnumLeaves.asm — DFS children; mark leaves; walk deepest leaf up
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN g_guiReCount:DWORD
EXTRN g_guiReHdr:BYTE
EXTRN GuiRe_CaptureHwnd:PROC
EXTRN GuiRe_Reset:PROC

PUBLIC GuiRe_EnumTree
PUBLIC GuiRe_ChildCb

.DATA
ALIGN 8
g_enumRoot      QWORD 0
g_deepLeaf      QWORD 0
g_deepDepth     DWORD 0

.CODE

; EnumChildWindows callback: RCX=hwnd RDX=lParam(depth+1 packed in low dword via shadow)
; We use lParam as parent depth+1 value.
GuiRe_ChildCb PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 40h
    .allocstack 40h
    .endprolog

    mov     rbx, rcx                 ; child
    mov     esi, edx                 ; depth

    mov     rcx, rbx
    mov     edx, esi
    call    GuiRe_CaptureHwnd

    ; track deepest as end-side seed
    cmp     esi, g_deepDepth
    jb      @f
    mov     g_deepDepth, esi
    mov     g_deepLeaf, rbx
@@:
    ; recurse children
    mov     eax, esi
    inc     eax
    mov     rcx, rbx
    lea     rdx, GuiRe_ChildCb
    mov     r8d, eax
    call    EnumChildWindows

    mov     eax, 1                   ; continue
    add     rsp, 40h
    pop     rsi
    pop     rbx
    ret
GuiRe_ChildCb ENDP

; RCX = root HWND — capture full tree leaf-out order (root first then DFS),
; then re-WalkUp from deepest leaf so hdr.leafHwnd is true end-side.
; RAX = node count
GuiRe_EnumTree PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 30h
    .allocstack 30h
    .endprolog

    mov     rbx, rcx
    call    GuiRe_Reset
    mov     g_enumRoot, rbx
    mov     g_deepLeaf, rbx
    mov     g_deepDepth, 0

    mov     rcx, rbx
    xor     edx, edx
    call    GuiRe_CaptureHwnd

    mov     rcx, rbx
    lea     rdx, GuiRe_ChildCb
    mov     r8d, 1
    call    EnumChildWindows

    ; Stamp end-side leaf + root into hdr (no reset — keep DFS nodes).
    lea     rax, g_guiReHdr
    mov     rcx, g_deepLeaf
    mov     [rax].GUIRE_HDR.leafHwnd, rcx
    mov     [rax].GUIRE_HDR.rootHwnd, rbx
    mov     ecx, g_guiReCount
    mov     [rax].GUIRE_HDR.count, ecx

    mov     eax, g_guiReCount
    add     rsp, 30h
    pop     rbx
    ret
GuiRe_EnumTree ENDP

END
