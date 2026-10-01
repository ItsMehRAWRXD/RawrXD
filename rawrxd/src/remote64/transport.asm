OPTION CASEMAP:NONE
include remote.inc
EXTERN WSAStartup:PROC
EXTERN WSACleanup:PROC
EXTERN WSAGetLastError:PROC
EXTERN socket:PROC
EXTERN bind:PROC
EXTERN listen:PROC
EXTERN accept:PROC
EXTERN connect:PROC
EXTERN getsockname:PROC
EXTERN setsockopt:PROC
EXTERN closesocket:PROC
EXTERN send:PROC
EXTERN recv:PROC
EXTERN shutdown:PROC
PUBLIC RemoteNetInit,RemoteNetCleanup,RemoteSendAll,RemoteRecvExact,RemoteSocketClose
PUBLIC RemoteSocketCreate,RemoteSocketBind,RemoteSocketListen,RemoteSocketAccept
PUBLIC RemoteSocketConnect,RemoteSocketSetTimeout,RemoteSocketLocalPort
INVALID_SOCKET EQU -1
SD_BOTH EQU 2
AF_INET EQU 2
SOCK_STREAM EQU 1
SOL_SOCKET EQU 0FFFFh
SO_RCVTIMEO EQU 1002h
SO_SNDTIMEO EQU 1001h
SOCKET_ERROR EQU -1
AF_INET_LEN EQU 16
.code

; Build a sockaddr_in in the caller-supplied 16-byte buffer.
; rcx=buffer rdx=ipv4 host-order dword r8d=port
FillSockAddr PROC
    mov WORD PTR [rcx],AF_INET
    mov eax,edx
    bswap eax
    mov [rcx+2],eax
    mov eax,r8d
    rol ax,8
    mov [rcx+4],ax
    mov qword PTR [rcx+8],0
    ret
FillSockAddr ENDP

RemoteSocketCreate PROC
    ; rcx=af rdx=type r8d=protocol -> rax socket, INVALID_SOCKET on failure
    sub rsp,28h
    call socket
    add rsp,28h
    ret
RemoteSocketCreate ENDP

RemoteSocketBind PROC
    ; rcx=sock rdx=ipv4 dword r8d=port -> eax 0 ok, R_IO fail
    ; frame: [rsp+00h..1Fh] shadow, [rsp+20h..2Fh] sockaddr_in
    push rbx
    sub rsp,30h
    mov rbx,rcx
    lea rcx,[rsp+20h]
    call FillSockAddr
    mov rcx,rbx
    lea rdx,[rsp+20h]
    mov r8d,AF_INET_LEN
    call bind
    test eax,eax
    jz rtb_ok
    mov eax,R_IO
    jmp rtb_done
rtb_ok:
    xor eax,eax
rtb_done:
    add rsp,30h
    pop rbx
    ret
RemoteSocketBind ENDP

RemoteSocketListen PROC
    ; rcx=sock edx=backlog
    sub rsp,28h
    call listen
    add rsp,28h
    test eax,eax
    jz rtl_ok
    mov eax,R_IO
    ret
rtl_ok:
    xor eax,eax
    ret
RemoteSocketListen ENDP

RemoteSocketAccept PROC
    ; rcx=listenSock rdx=peerBuffer(>=16) -> rax clientSock, INVALID_SOCKET fail
    ; frame: [rsp+00h..1Fh] shadow, [rsp+20h..2Fh] peer sockaddr, [rsp+30h] addrlen
    push rbx
    sub rsp,40h
    mov rbx,rcx
    mov DWORD PTR [rsp+30h],AF_INET_LEN
    mov rcx,rbx
    lea rdx,[rsp+20h]
    lea r8,[rsp+30h]
    call accept
    add rsp,40h
    pop rbx
    ret
RemoteSocketAccept ENDP

RemoteSocketConnect PROC
    ; rcx=sock rdx=ipv4 dword r8d=port -> eax 0 ok, R_IO fail
    ; frame: [rsp+00h..1Fh] shadow, [rsp+20h..2Fh] sockaddr_in
    push rbx
    sub rsp,30h
    mov rbx,rcx
    lea rcx,[rsp+20h]
    call FillSockAddr
    mov rcx,rbx
    lea rdx,[rsp+20h]
    mov r8d,AF_INET_LEN
    call connect
    test eax,eax
    jz rtc_ok
    mov eax,R_IO
    jmp rtc_done
rtc_ok:
    xor eax,eax
rtc_done:
    add rsp,30h
    pop rbx
    ret
RemoteSocketConnect ENDP

RemoteSocketSetTimeout PROC
    ; rcx=sock edx=milliseconds (0 disables). Applies to both send and recv
    ; so a dead peer cannot stall the frame loop forever.
    ; frame: [rsp+00h..1Fh] shadow, [rsp+28h] 4-byte timeval value
    push rbx
    push rsi
    sub rsp,38h
    mov rbx,rcx
    mov esi,edx
    lea r8,[rsp+28h]
    mov [rsp+20h],r8
    mov r9d,4
    mov [rsp+28h],esi
    mov edx,SO_RCVTIMEO
    call setsockopt
    test eax,eax
    jnz rst_fail
    lea r8,[rsp+28h]
    mov [rsp+20h],r8
    mov r9d,4
    mov [rsp+28h],esi
    mov edx,SO_SNDTIMEO
    call setsockopt
    test eax,eax
    jnz rst_fail
    xor eax,eax
    jmp rst_done
rst_fail:
    mov eax,R_IO
rst_done:
    add rsp,38h
    pop rsi
    pop rbx
    ret
RemoteSocketSetTimeout ENDP

RemoteSocketLocalPort PROC
    ; rcx=sock -> eax host-order port, R_IO on failure
    ; frame: [rsp+00h..1Fh] shadow, [rsp+20h..2Fh] sockaddr_in, [rsp+30h] addrlen
    push rbx
    sub rsp,40h
    mov rbx,rcx
    lea rdx,[rsp+20h]
    lea r8,[rsp+30h]
    mov DWORD PTR [rsp+30h],AF_INET_LEN
    mov rcx,rbx
    call getsockname
    test eax,eax
    jnz rslp_fail
    movzx eax,WORD PTR [rsp+22h]
    rol ax,8
    add rsp,40h
    pop rbx
    ret
rslp_fail:
    mov eax,R_IO
    add rsp,40h
    pop rbx
    ret
RemoteSocketLocalPort ENDP

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
