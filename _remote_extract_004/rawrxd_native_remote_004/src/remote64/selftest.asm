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
dec BYTE 64 DUP(0)
hdr REMOTE_HEADER <>
sess REMOTE_SESSION <>
.code
RemoteSelfTest PROC
 sub rsp,48h
 lea rcx,src
 mov edx,LENGTHOF src
 lea r8,enc
 mov r9d,LENGTHOF enc
 call RemoteRleEncode
 test rax,rax
 jz st_fail
 mov r10,rax
 lea rcx,enc
 mov rdx,r10
 lea r8,dec
 mov r9d,LENGTHOF dec
 call RemoteRleDecode
 cmp rax,LENGTHOF src
 jne st_fail
 xor r11d,r11d
st_cmp: cmp r11d,LENGTHOF src
 jae st_proto
 mov al,src[r11]
 cmp al,dec[r11]
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
 ret
RemoteSelfTest ENDP
END
