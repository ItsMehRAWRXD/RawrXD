; GuiRe_FromPoint.asm — hit-test leaf under cursor/coords, then walk up
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN GuiRe_WalkUp:PROC

PUBLIC GuiRe_FromPoint
PUBLIC GuiRe_FromMain

.DATA
szMainCls DB "RawrXD_IDE_MainWindow", 0

.CODE

; ECX=x  EDX=y  → WindowFromPoint → WalkUp
; RAX = node count
GuiRe_FromPoint PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 30h
    .allocstack 30h
    .endprolog

    mov     eax, ecx
    mov     ecx, edx
    shl     rcx, 32
    or      rcx, rax                 ; POINT in RCX
    call    WindowFromPoint
    mov     rbx, rax
    test    rbx, rbx
    jz      none
    mov     rcx, rbx
    call    GuiRe_WalkUp
    jmp     done
none:
    xor     eax, eax
done:
    add     rsp, 30h
    pop     rbx
    ret
GuiRe_FromPoint ENDP

; Find live main window by class, treat as root; capture root only then kids via Enum.
; For end-side-out of whole tree: find a deep child first — see GuiRe_EnumLeaves.
; RAX = node count after WalkUp from main (depth-0 = main as “leaf” of this call)
GuiRe_FromMain PROC FRAME
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    lea     rcx, szMainCls
    xor     edx, edx
    call    FindWindowA
    test    rax, rax
    jz      @f
    mov     rcx, rax
    call    GuiRe_WalkUp
@@:
    add     rsp, 28h
    ret
GuiRe_FromMain ENDP

END
