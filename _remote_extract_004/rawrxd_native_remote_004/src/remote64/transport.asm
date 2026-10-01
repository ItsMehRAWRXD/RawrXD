OPTION CASEMAP:NONE
include remote.inc
EXTERN WSAStartup:PROC
EXTERN WSACleanup:PROC
EXTERN socket:PROC
EXTERN closesocket:PROC
EXTERN send:PROC
EXTERN recv:PROC
EXTERN shutdown:PROC
PUBLIC RemoteNetInit,RemoteNetCleanup,RemoteSendAll,RemoteRecvExact,RemoteSocketClose
INVALID_SOCKET EQU -1
SD_BOTH EQU 2
.code
RemoteNetInit PROC
 ; rcx -> >= 400 byte WSADATA storage
 mov rdx,rcx
 mov ecx,0202h
 sub rsp,28h
 call WSAStartup
 add rsp,28h
 ret
RemoteNetInit ENDP
RemoteNetCleanup PROC
 sub rsp,28h
 call WSACleanup
 add rsp,28h
 ret
RemoteNetCleanup ENDP
RemoteSendAll PROC
 ; rcx=socket rdx=buf r8=len
 push rbx
 push rsi
 push rdi
 sub rsp,20h
 mov rbx,rcx
 mov rsi,rdx
 mov rdi,r8
rsa_loop: test rdi,rdi
 jz rsa_ok
 mov rcx,rbx
 mov rdx,rsi
 mov r8d,edi
 xor r9d,r9d
 call send
 cmp eax,0
 jle rsa_fail
 movsxd r10,eax
 add rsi,r10
 sub rdi,r10
 jmp rsa_loop
rsa_ok: xor eax,eax
 jmp rsa_done
rsa_fail: mov eax,R_IO
rsa_done: add rsp,20h
 pop rdi
 pop rsi
 pop rbx
 ret
RemoteSendAll ENDP
RemoteRecvExact PROC
 ; rcx=socket rdx=buf r8=len
 push rbx
 push rsi
 push rdi
 sub rsp,20h
 mov rbx,rcx
 mov rsi,rdx
 mov rdi,r8
rre_loop: test rdi,rdi
 jz rre_ok
 mov rcx,rbx
 mov rdx,rsi
 mov r8d,edi
 xor r9d,r9d
 call recv
 cmp eax,0
 jle rre_fail
 movsxd r10,eax
 add rsi,r10
 sub rdi,r10
 jmp rre_loop
rre_ok: xor eax,eax
 jmp rre_done
rre_fail: mov eax,R_IO
rre_done: add rsp,20h
 pop rdi
 pop rsi
 pop rbx
 ret
RemoteRecvExact ENDP
RemoteSocketClose PROC
 push rbx
 sub rsp,20h
 mov rbx,rcx
 cmp rbx,INVALID_SOCKET
 je rsc_done
 mov rcx,rbx
 mov edx,SD_BOTH
 call shutdown
 mov rcx,rbx
 call closesocket
rsc_done: add rsp,20h
 pop rbx
 ret
RemoteSocketClose ENDP
END
