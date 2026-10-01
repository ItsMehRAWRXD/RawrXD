OPTION CASEMAP:NONE
include remote.inc
EXTERN RemoteRleEncode:PROC
EXTERN RemoteRleDecode:PROC
EXTERN RemoteHeaderWrite:PROC
EXTERN RemoteHeaderValidate:PROC
EXTERN RemoteSessionInit:PROC
EXTERN RemoteSessionConnected:PROC
EXTERN RemoteSessionAuthorizeControl:PROC
PUBLIC RemoteSelfTest
.data
src BYTE 1,1,1,1,2,3,3,4,4,4,4,4,5,6,7,7
enc BYTE 64 DUP(0)
decBuf BYTE 64 DUP(0)
hdr REMOTE_HEADER <>
sess REMOTE_SESSION <>
.code
RemoteSelfTest PROC
 ; BUG 61.6: the byte-wise compare indexed the .data arrays directly
 ; (`src[r11]`, `decBuf[r11]`). Register-indexed access to a data symbol makes
 ; ml64 emit an ADDR32 absolute relocation, which fails at link time with
 ; LNK2017 on x64. The bases are now taken once with LEA (RIP-relative) and
 ; indexed off registers.
 push rbx
 push rsi
 sub rsp,48h
 lea rcx,src
 mov edx,SIZEOF src
 lea r8,enc
 mov r9d,SIZEOF enc
 call RemoteRleEncode
 test rax,rax
 jz st_fail
 mov r10,rax
 lea rcx,enc
 mov rdx,r10
 lea r8,decBuf
 mov r9d,SIZEOF decBuf
 call RemoteRleDecode
 cmp rax,SIZEOF src
 jne st_fail
 lea rbx,src
 lea rsi,decBuf
 xor r11d,r11d
st_cmp: cmp r11d,SIZEOF src
 jae st_proto
 mov al,[rbx+r11]
 cmp al,[rsi+r11]
 jne st_fail
 inc r11d
 jmp st_cmp
st_proto:
 lea rcx,hdr
 mov edx,MSG_PING
 mov r8d,1
 xor r9d,r9d
 call RemoteHeaderWrite
 lea rcx,hdr
 mov edx,1
 call RemoteHeaderValidate
 test eax,eax
 jne st_fail
 lea rcx,sess
 call RemoteSessionInit
 lea rcx,sess
 call RemoteSessionConnected
 lea rcx,sess
 call RemoteSessionAuthorizeControl
 cmp eax,R_AUTH ; must fail before auth
 jne st_fail
 xor eax,eax
 jmp st_done
st_fail: mov eax,R_ERR
st_done: add rsp,48h
 pop rsi
 pop rbx
 ret
RemoteSelfTest ENDP
END
