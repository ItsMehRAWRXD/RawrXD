OPTION CASEMAP:NONE
EXTERN GetWindowRect:PROC
PUBLIC RemoteWindow_GetRect
.code
RemoteWindow_GetRect PROC
    ; rcx=HWND, rdx=RECT*
    sub rsp,28h
    call GetWindowRect
    add rsp,28h
    ret
RemoteWindow_GetRect ENDP
END
