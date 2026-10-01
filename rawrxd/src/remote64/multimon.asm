OPTION CASEMAP:NONE
EXTERN GetSystemMetrics:PROC
PUBLIC RemoteDisplay_GetVirtualDesktop
SM_XVIRTUALSCREEN EQU 76
SM_YVIRTUALSCREEN EQU 77
SM_CXVIRTUALSCREEN EQU 78
SM_CYVIRTUALSCREEN EQU 79
.code
RemoteDisplay_GetVirtualDesktop PROC
    ; rcx -> 4 signed dwords x,y,w,h
    push rbx
    sub rsp,20h
    mov rbx,rcx
    mov ecx,SM_XVIRTUALSCREEN
    call GetSystemMetrics
    mov [rbx+0],eax
    mov ecx,SM_YVIRTUALSCREEN
    call GetSystemMetrics
    mov [rbx+4],eax
    mov ecx,SM_CXVIRTUALSCREEN
    call GetSystemMetrics
    mov [rbx+8],eax
    mov ecx,SM_CYVIRTUALSCREEN
    call GetSystemMetrics
    mov [rbx+12],eax
    mov eax,1
    add rsp,20h
    pop rbx
    ret
RemoteDisplay_GetVirtualDesktop ENDP
END
