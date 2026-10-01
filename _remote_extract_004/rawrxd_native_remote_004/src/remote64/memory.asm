OPTION CASEMAP:NONE
include remote.inc
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
PUBLIC RemoteAlloc, RemoteFree, RemoteZero
MEM_COMMIT EQU 1000h
MEM_RESERVE EQU 2000h
MEM_RELEASE EQU 8000h
PAGE_READWRITE EQU 4
.code
RemoteAlloc PROC
 ; rcx=bytes
 mov rdx,rcx
 xor ecx,ecx
 mov r8d,MEM_COMMIT or MEM_RESERVE
 mov r9d,PAGE_READWRITE
 sub rsp,28h
 call VirtualAlloc
 add rsp,28h
 ret
RemoteAlloc ENDP
RemoteFree PROC
 test rcx,rcx
 jz rf_done
 xor edx,edx
 mov r8d,MEM_RELEASE
 sub rsp,28h
 call VirtualFree
 add rsp,28h
rf_done: ret
RemoteFree ENDP
RemoteZero PROC
 ; rcx=p, rdx=n
 xor eax,eax
rz_loop: test rdx,rdx
 jz rz_done
 mov BYTE PTR [rcx],0
 inc rcx
 dec rdx
 jmp rz_loop
rz_done: ret
RemoteZero ENDP
END
