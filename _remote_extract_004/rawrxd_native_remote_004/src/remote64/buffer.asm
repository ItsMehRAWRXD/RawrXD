OPTION CASEMAP:NONE
include remote.inc
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteBufferInit,RemoteBufferDestroy,RemoteBufferAppend,RemoteBufferReset
.code
RemoteBufferInit PROC
 ; rcx=buf rdx=capacity
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov QWORD PTR [rbx].REMOTE_BUFFER.ptr,0
 mov QWORD PTR [rbx].REMOTE_BUFFER.size,0
 mov [rbx].REMOTE_BUFFER.capacity,rdx
 mov rcx,rdx
 call RemoteAlloc
 mov [rbx].REMOTE_BUFFER.ptr,rax
 test rax,rax
 setnz al
 movzx eax,al
 add rsp,20h
 pop rbx
 ret
RemoteBufferInit ENDP
RemoteBufferDestroy PROC
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov rcx,[rbx].REMOTE_BUFFER.ptr
 call RemoteFree
 mov QWORD PTR [rbx].REMOTE_BUFFER.ptr,0
 mov QWORD PTR [rbx].REMOTE_BUFFER.size,0
 mov QWORD PTR [rbx].REMOTE_BUFFER.capacity,0
 add rsp,20h
 pop rbx
 ret
RemoteBufferDestroy ENDP
RemoteBufferReset PROC
 mov QWORD PTR [rcx].REMOTE_BUFFER.size,0
 xor eax,eax
 ret
RemoteBufferReset ENDP
RemoteBufferAppend PROC
 ; rcx=buf rdx=src r8=len
 mov r9,[rcx].REMOTE_BUFFER.size
 mov rax,r9
 add rax,r8
 jc rba_fail
 cmp rax,[rcx].REMOTE_BUFFER.capacity
 ja rba_fail
 mov r10,[rcx].REMOTE_BUFFER.ptr
 add r10,r9
 mov [rcx].REMOTE_BUFFER.size,rax
 test r8,r8
 jz rba_ok
rba_copy: mov al,[rdx]
 mov [r10],al
 inc rdx
 inc r10
 dec r8
 jnz rba_copy
rba_ok: xor eax,eax
 ret
rba_fail: mov eax,R_BOUNDS
 ret
RemoteBufferAppend ENDP
END
