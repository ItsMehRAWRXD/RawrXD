OPTION CASEMAP:NONE
include remote.inc
EXTERN SendInput:PROC
PUBLIC RemoteInputDispatch
.code
RemoteInputDispatch PROC
 ; rcx=session rdx=INPUT* r8d=count r9d=inputStructSize
 cmp DWORD PTR [rcx].REMOTE_SESSION.authenticated,1
 jne rid_no
 cmp DWORD PTR [rcx].REMOTE_SESSION.controlAllowed,1
 jne rid_no
 cmp DWORD PTR [rcx].REMOTE_SESSION.state,S_CONTROL
 jne rid_no
 mov rcx,r8
 mov r8d,r9d
 ; rdx already INPUT*
 sub rsp,28h
 call SendInput
 add rsp,28h
 test eax,eax
 jz rid_err
 xor eax,eax
 ret
rid_no: mov eax,R_AUTH
 ret
rid_err: mov eax,R_ERR
 ret
RemoteInputDispatch ENDP
END
