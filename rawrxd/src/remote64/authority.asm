OPTION CASEMAP:NONE
include remote.inc
EXTERN RemoteSessionInit:PROC
EXTERN RemoteSessionAuthorizeControl:PROC
EXTERN RemoteSessionRevokeControl:PROC
PUBLIC RemoteAuthorityInit,RemoteAuthorityLocalApprove,RemoteAuthorityLocalRevoke,RemoteAuthorityCanObserve,RemoteAuthorityCanControl
.data
align 16
g_session REMOTE_SESSION <>
.code
RemoteAuthorityInit PROC
 lea rcx,g_session
 sub rsp,28h
 call RemoteSessionInit
 add rsp,28h
 ret
RemoteAuthorityInit ENDP
RemoteAuthorityLocalApprove PROC
 lea rcx,g_session
 sub rsp,28h
 call RemoteSessionAuthorizeControl
 add rsp,28h
 ret
RemoteAuthorityLocalApprove ENDP
RemoteAuthorityLocalRevoke PROC
 lea rcx,g_session
 sub rsp,28h
 call RemoteSessionRevokeControl
 add rsp,28h
 ret
RemoteAuthorityLocalRevoke ENDP
RemoteAuthorityCanObserve PROC
 xor eax,eax
 cmp DWORD PTR g_session.authenticated,1
 setz al
 ret
RemoteAuthorityCanObserve ENDP
RemoteAuthorityCanControl PROC
 xor eax,eax
 cmp DWORD PTR g_session.authenticated,1
 jne @F
 cmp DWORD PTR g_session.controlAllowed,1
 jne @F
 mov eax,1
@@: ret
RemoteAuthorityCanControl ENDP
END
