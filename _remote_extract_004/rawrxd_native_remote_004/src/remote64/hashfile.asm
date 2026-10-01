OPTION CASEMAP:NONE
include remote.inc
EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptCreateHash:PROC
EXTERN BCryptHashData:PROC
EXTERN BCryptFinishHash:PROC
EXTERN BCryptDestroyHash:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC
PUBLIC RemoteHash_BufferSha256
.data
sha256Name dw 'S','H','A','2','5','6',0
.code
RemoteHash_BufferSha256 PROC
    ; rcx=data rdx=len r8=32-byte output; NTSTATUS in eax
    push rbx
    push rsi
    push rdi
    sub rsp,50h
    mov rsi,rcx
    mov edi,edx
    mov rbx,r8
    lea rcx,[rsp+30h]
    lea rdx,sha256Name
    xor r8d,r8d
    xor r9d,r9d
    call BCryptOpenAlgorithmProvider
    test eax,eax
    js hb_done
    mov rcx,[rsp+30h]
    lea rdx,[rsp+38h]
    xor r8d,r8d
    xor r9d,r9d
    mov QWORD PTR [rsp+20h],0
    mov DWORD PTR [rsp+28h],0
    call BCryptCreateHash
    test eax,eax
    js hb_close
    mov rcx,[rsp+38h]
    mov rdx,rsi
    mov r8d,edi
    xor r9d,r9d
    call BCryptHashData
    test eax,eax
    js hb_destroy
    mov rcx,[rsp+38h]
    mov rdx,rbx
    mov r8d,32
    xor r9d,r9d
    call BCryptFinishHash
hb_destroy:
    push rax
    mov rcx,[rsp+40h]
    call BCryptDestroyHash
    pop rax
hb_close:
    push rax
    mov rcx,[rsp+38h]
    xor edx,edx
    call BCryptCloseAlgorithmProvider
    pop rax
hb_done:
    add rsp,50h
    pop rdi
    pop rsi
    pop rbx
    ret
RemoteHash_BufferSha256 ENDP
END
