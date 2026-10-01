OPTION CASEMAP:NONE
include remote.inc
EXTERN BCryptGenRandom:PROC
EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC
EXTERN BCryptGetProperty:PROC
EXTERN BCryptCreateHash:PROC
EXTERN BCryptHashData:PROC
EXTERN BCryptFinishHash:PROC
EXTERN BCryptDestroyHash:PROC
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteRandom,RemoteHmacSha256,RemoteConstantTimeEqual
BCRYPT_USE_SYSTEM_PREFERRED_RNG EQU 2
BCRYPT_ALG_HANDLE_HMAC_FLAG EQU 8
.data
align 2
sha256Name WORD 'S','H','A','2','5','6',0
objLenName WORD 'O','b','j','e','c','t','L','e','n','g','t','h',0
.code
RemoteRandom PROC
 ; rcx=dst rdx=len
 ; BCRYPTGENRANDOM(hAlgorithm, pbBuffer, cbBuffer, dwFlags)
 ;   rcx=hAlgorithm rdx=pbBuffer r8=cbBuffer r9=dwFlags
 ; BUG 62.1: the previous version loaded r8d=2 and rdx=dst, which passed the
 ; flag constant as the byte count and left dwFlags (r9) uninitialised. The
 ; call would have returned 2 bytes with a garbage flag word.
    mov r8,rdx
    mov rdx,rcx
    mov r9d,BCRYPT_USE_SYSTEM_PREFERRED_RNG
    xor ecx,ecx
    test r8,r8
    jz rr_len0
    sub rsp,28h
    call BCryptGenRandom
    add rsp,28h
    ret
rr_len0:
    xor eax,eax
    ret
RemoteRandom ENDP
RemoteConstantTimeEqual PROC
 ; rcx=a rdx=b r8=len => eax 1 equal
 xor r9d,r9d
rcte_loop: test r8,r8
 jz rcte_done
 mov al,[rcx]
 xor al,[rdx]
 movzx eax,al
 or r9d,eax
 inc rcx
 inc rdx
 dec r8
 jmp rcte_loop
rcte_done: xor eax,eax
 test r9d,r9d
 sete al
 ret
RemoteConstantTimeEqual ENDP
RemoteHmacSha256 PROC
 ; rcx=key rdx=keyLen r8=data r9=dataLen; stack out32
 push rbx
 push rsi
 push rdi
 push r12
 push r13
 sub rsp,70h
 mov r12,rcx
 mov r13,rdx
 mov rsi,r8
 mov rdi,r9
 mov QWORD PTR [rsp+40h],0 ; alg
 mov QWORD PTR [rsp+48h],0 ; hash
 lea rcx,[rsp+40h]
 lea rdx,sha256Name
 xor r8d,r8d
 mov r9d,BCRYPT_ALG_HANDLE_HMAC_FLAG
 call BCryptOpenAlgorithmProvider
 test eax,eax
 js rhs_fail
 mov rbx,[rsp+40h]
 mov DWORD PTR [rsp+58h],0
 mov DWORD PTR [rsp+5Ch],0
 mov rcx,rbx
 lea rdx,objLenName
 lea r8,[rsp+58h]
 mov r9d,4
 lea rax,[rsp+5Ch]
 mov [rsp+20h],rax
 mov DWORD PTR [rsp+28h],0
 call BCryptGetProperty
 test eax,eax
 js rhs_failclose
 mov ecx,[rsp+58h]
 call RemoteAlloc
 test rax,rax
 jz rhs_failclose
 mov [rsp+50h],rax
 mov rcx,rbx
 lea rdx,[rsp+48h]
 mov r8,rax
 mov r9d,[rsp+58h]
 mov [rsp+20h],r12
 mov DWORD PTR [rsp+28h],r13d
 mov DWORD PTR [rsp+30h],0
 call BCryptCreateHash
 test eax,eax
 js rhs_free
 mov rcx,[rsp+48h]
 mov rdx,rsi
 mov r8d,edi
 xor r9d,r9d
 call BCryptHashData
 test eax,eax
 js rhs_hashdestroy
 mov rcx,[rsp+48h]
 mov rdx,[rsp+0C0h] ; caller stack out after pushes/sub
 mov r8d,32
 xor r9d,r9d
 call BCryptFinishHash
 mov r13d,eax
 mov rcx,[rsp+48h]
 call BCryptDestroyHash
 mov rcx,[rsp+50h]
 call RemoteFree
 mov rcx,rbx
 xor edx,edx
 call BCryptCloseAlgorithmProvider
 mov eax,r13d
 jmp rhs_done
rhs_hashdestroy: mov rcx,[rsp+48h]
 call BCryptDestroyHash
rhs_free: mov rcx,[rsp+50h]
 call RemoteFree
rhs_failclose: mov rcx,rbx
 xor edx,edx
 call BCryptCloseAlgorithmProvider
rhs_fail: mov eax,R_ERR
rhs_done: add rsp,70h
 pop r13
 pop r12
 pop rdi
 pop rsi
 pop rbx
 ret
RemoteHmacSha256 ENDP
END
