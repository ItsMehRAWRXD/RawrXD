OPTION CASEMAP:NONE
EXTERN GetSystemMetrics:PROC
PUBLIC RemoteDisplayRead
SM_XVIRTUALSCREEN EQU 76
SM_YVIRTUALSCREEN EQU 77
SM_CXVIRTUALSCREEN EQU 78
SM_CYVIRTUALSCREEN EQU 79
.code
RemoteDisplayRead PROC
 ; rcx -> 4 DWORD {x,y,w,h}
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov ecx,SM_XVIRTUALSCREEN
 call GetSystemMetrics
 mov [rbx],eax
 mov ecx,SM_YVIRTUALSCREEN
 call GetSystemMetrics
 mov [rbx+4],eax
 mov ecx,SM_CXVIRTUALSCREEN
 call GetSystemMetrics
 mov [rbx+8],eax
 mov ecx,SM_CYVIRTUALSCREEN
 call GetSystemMetrics
 mov [rbx+12],eax
 xor eax,eax
 add rsp,20h
 pop rbx
 ret
RemoteDisplayRead ENDP
END
