OPTION CASEMAP:NONE
include remote.inc
EXTERN RemoteRandom:PROC
EXTERN RemoteHmacSha256:PROC
EXTERN RemoteConstantTimeEqual:PROC
PUBLIC RemoteAuthBegin,RemoteAuthMakeProof,RemoteAuthVerifyProof
.code
RemoteAuthBegin PROC
 ; rcx=session
 push rbx
 sub rsp,20h
 mov rbx,rcx
 lea rcx,[rbx].REMOTE_SESSION.challenge
 mov edx,32
 call RemoteRandom
 test eax,eax
 js rab_fail
 mov DWORD PTR [rbx].REMOTE_SESSION.state,S_PAIRING
 xor eax,eax
 jmp rab_done
rab_fail: mov eax,R_ERR
rab_done: add rsp,20h
 pop rbx
 ret
RemoteAuthBegin ENDP
RemoteAuthMakeProof PROC
 ; rcx=session rdx=secret r8=secretLen r9=out32
 sub rsp,38h
 mov [rsp+20h],r9
 mov r9d,32
 lea rax,[rcx].REMOTE_SESSION.challenge
 mov rcx,rdx
 mov rdx,r8
 mov r8,rax
 call RemoteHmacSha256
 add rsp,38h
 ret
RemoteAuthMakeProof ENDP
RemoteAuthVerifyProof PROC
 ; rcx=session rdx=secret r8=secretLen r9=proof32
 push rbx
 push rsi
 sub rsp,58h
 mov rbx,rcx
 mov rsi,r9
 lea r9,[rsp+30h]
 mov rcx,rbx
 call RemoteAuthMakeProof
 test eax,eax
 js rav_fail
 lea rcx,[rsp+30h]
 mov rdx,rsi
 mov r8d,32
 call RemoteConstantTimeEqual
 cmp eax,1
 jne rav_fail
 mov DWORD PTR [rbx].REMOTE_SESSION.authenticated,1
 mov DWORD PTR [rbx].REMOTE_SESSION.state,S_VIEW_ONLY
 xor eax,eax
 jmp rav_done
rav_fail: mov DWORD PTR [rbx].REMOTE_SESSION.authenticated,0
 mov eax,R_AUTH
rav_done: add rsp,58h
 pop rsi
 pop rbx
 ret
RemoteAuthVerifyProof ENDP
END
