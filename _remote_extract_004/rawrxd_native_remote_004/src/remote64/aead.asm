OPTION CASEMAP:NONE
include remote.inc
EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC
EXTERN BCryptSetProperty:PROC
EXTERN BCryptGetProperty:PROC
EXTERN BCryptGenerateSymmetricKey:PROC
EXTERN BCryptDestroyKey:PROC
EXTERN BCryptEncrypt:PROC
EXTERN BCryptDecrypt:PROC
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteAeadEncrypt,RemoteAeadDecrypt
.data
align 2
aesName WORD 'A','E','S',0
chainName WORD 'C','h','a','i','n','i','n','g','M','o','d','e',0
gcmName WORD 'C','h','a','i','n','i','n','g','M','o','d','e','G','C','M',0
objName WORD 'O','b','j','e','c','t','L','e','n','g','t','h',0
.code
; Internal worker: r12 mode 0 encrypt 1 decrypt
AeadWorker PROC
 ; rcx=key32 rdx=nonce12 r8=in r9=inLen
 ; stack: out, tag16, aad, aadLen
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 push r14
 push r15
 sub rsp,0B0h
 mov r13,rcx
 mov r14,rdx
 mov r15,r8
 mov rdi,r9
 mov QWORD PTR [rsp+60h],0
 lea rcx,[rsp+60h]
 lea rdx,aesName
 xor r8d,r8d
 xor r9d,r9d
 call BCryptOpenAlgorithmProvider
 test eax,eax
 js aw_fail
 mov rbx,[rsp+60h]
 mov rcx,rbx
 lea rdx,chainName
 lea r8,gcmName
 mov r9d,30 ; bytes incl terminator
 mov DWORD PTR [rsp+20h],0
 call BCryptSetProperty
 test eax,eax
 js aw_close
 mov DWORD PTR [rsp+70h],0
 mov DWORD PTR [rsp+74h],0
 mov rcx,rbx
 lea rdx,objName
 lea r8,[rsp+70h]
 mov r9d,4
 lea rax,[rsp+74h]
 mov [rsp+20h],rax
 mov DWORD PTR [rsp+28h],0
 call BCryptGetProperty
 test eax,eax
 js aw_close
 mov ecx,[rsp+70h]
 call RemoteAlloc
 test rax,rax
 jz aw_close
 mov [rsp+68h],rax
 mov rcx,rbx
 lea rdx,[rsp+78h] ; key handle
 mov r8,rax
 mov r9d,[rsp+70h]
 mov [rsp+20h],r13
 mov DWORD PTR [rsp+28h],32
 mov DWORD PTR [rsp+30h],0
 call BCryptGenerateSymmetricKey
 test eax,eax
 js aw_free
 ; AUTH_INFO at rsp+80
 lea rsi,[rsp+80h]
 xor eax,eax
 mov ecx,SIZEOF AUTH_INFO/8
aw_zero: mov QWORD PTR [rsi+rax*8],0
 inc eax
 loop aw_zero
 mov DWORD PTR [rsi].AUTH_INFO.cbSize,SIZEOF AUTH_INFO
 mov DWORD PTR [rsi].AUTH_INFO.dwInfoVersion,1
 mov [rsi].AUTH_INFO.pbNonce,r14
 mov DWORD PTR [rsi].AUTH_INFO.cbNonce,12
 ; caller args after 7 pushes + B0 = E8; return + shadow => first stack arg at rsp+110h
 mov rax,[rsp+110h]
 mov [rsi].AUTH_INFO.pbTag,rax
 mov DWORD PTR [rsi].AUTH_INFO.cbTag,16
 mov rax,[rsp+120h]
 mov [rsi].AUTH_INFO.pbAuthData,rax
 mov eax,DWORD PTR [rsp+128h]
 mov [rsi].AUTH_INFO.cbAuthData,eax
 mov rcx,[rsp+78h]
 mov rdx,r15
 mov r8d,edi
 mov r9,rsi
 xor eax,eax
 mov [rsp+20h],rax
 mov rax,[rsp+108h]
 mov [rsp+28h],rax
 mov DWORD PTR [rsp+30h],edi
 lea rax,[rsp+7Ch]
 mov [rsp+38h],rax
 mov DWORD PTR [rsp+40h],0
 cmp r12d,0
 jne aw_dec
 call BCryptEncrypt
 jmp aw_after
aw_dec: call BCryptDecrypt
aw_after: mov r13d,eax
 mov rcx,[rsp+78h]
 call BCryptDestroyKey
 mov rcx,[rsp+68h]
 call RemoteFree
 mov rcx,rbx
 xor edx,edx
 call BCryptCloseAlgorithmProvider
 mov eax,r13d
 jmp aw_done
aw_free: mov rcx,[rsp+68h]
 call RemoteFree
aw_close: mov rcx,rbx
 xor edx,edx
 call BCryptCloseAlgorithmProvider
aw_fail: mov eax,R_ERR
aw_done: add rsp,0B0h
 pop r15
 pop r14
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
AeadWorker ENDP
RemoteAeadEncrypt PROC
 xor r12d,r12d
 jmp AeadWorker
RemoteAeadEncrypt ENDP
RemoteAeadDecrypt PROC
 mov r12d,1
 jmp AeadWorker
RemoteAeadDecrypt ENDP
END
