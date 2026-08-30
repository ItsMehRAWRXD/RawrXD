; GuiRe_Edit.asm — agent-style mutate (text / enable / show)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

PUBLIC GuiRe_SetTextA
PUBLIC GuiRe_SetEnable
PUBLIC GuiRe_SetShow
PUBLIC GuiRe_SendCmd

.CODE

; RCX=HWND RDX=LPCSTR → SetWindowTextA; RAX=BOOL
GuiRe_SetTextA PROC FRAME
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    call    SetWindowTextA
    add     rsp, 28h
    ret
GuiRe_SetTextA ENDP

; RCX=HWND EDX=enable(0/1)
GuiRe_SetEnable PROC FRAME
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    call    EnableWindow
    add     rsp, 28h
    ret
GuiRe_SetEnable ENDP

; RCX=HWND EDX=SW_* 
GuiRe_SetShow PROC FRAME
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    call    ShowWindow
    add     rsp, 28h
    ret
GuiRe_SetShow ENDP

; RCX=HWND EDX=msg R8=wParam R9=lParam — raw SendMessageA
GuiRe_SendCmd PROC FRAME
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    call    SendMessageA
    add     rsp, 28h
    ret
GuiRe_SendCmd ENDP

END
