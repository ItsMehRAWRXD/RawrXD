OPTION CASEMAP:NONE
include remote.inc
PUBLIC RemoteSessionInit,RemoteSessionConnected,RemoteSessionAuthorizeControl,RemoteSessionRevokeControl,RemoteSessionAcceptSequence,RemoteSessionNextSequence,RemoteSessionClose
.code
RemoteSessionInit PROC
 xor eax,eax
 mov DWORD PTR [rcx].REMOTE_SESSION.state,S_DISCONNECTED
 mov DWORD PTR [rcx].REMOTE_SESSION.authenticated,0
 mov DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,0
 mov [rcx].REMOTE_SESSION.txSequence,rax
 mov [rcx].REMOTE_SESSION.rxSequence,rax
 ret
RemoteSessionInit ENDP
RemoteSessionConnected PROC
 mov DWORD PTR [rcx].REMOTE_SESSION.state,S_CONNECTED
 mov DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,0
 xor eax,eax
 ret
RemoteSessionConnected ENDP
RemoteSessionAuthorizeControl PROC
 cmp DWORD PTR [rcx].REMOTE_SESSION.authenticated,1
 jne rsa_no
 cmp DWORD PTR [rcx].REMOTE_SESSION.state,S_VIEW_ONLY
 jne rsa_no
 mov DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,1
 mov DWORD PTR [rcx].REMOTE_SESSION.state,S_CONTROL
 xor eax,eax
 ret
rsa_no: mov eax,R_AUTH
 ret
RemoteSessionAuthorizeControl ENDP
RemoteSessionRevokeControl PROC
 mov DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,0
 cmp DWORD PTR [rcx].REMOTE_SESSION.authenticated,1
 jne @F
 mov DWORD PTR [rcx].REMOTE_SESSION.state,S_VIEW_ONLY
@@: xor eax,eax
 ret
RemoteSessionRevokeControl ENDP
RemoteSessionAcceptSequence PROC
 ; rcx=session rdx=received; strictly increasing
 mov rax,[rcx].REMOTE_SESSION.rxSequence
 cmp rdx,rax
 jbe rsas_bad
 mov [rcx].REMOTE_SESSION.rxSequence,rdx
 xor eax,eax
 ret
rsas_bad: mov eax,R_AUTH
 ret
RemoteSessionAcceptSequence ENDP
RemoteSessionNextSequence PROC
 mov rax,[rcx].REMOTE_SESSION.txSequence
 inc rax
 mov [rcx].REMOTE_SESSION.txSequence,rax
 ret
RemoteSessionNextSequence ENDP
RemoteSessionClose PROC
 mov DWORD PTR [rcx].REMOTE_SESSION.state,S_DISCONNECTED
 mov DWORD PTR [rcx].REMOTE_SESSION.authenticated,0
 mov DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,0
 xor eax,eax
 ret
RemoteSessionClose ENDP
END
