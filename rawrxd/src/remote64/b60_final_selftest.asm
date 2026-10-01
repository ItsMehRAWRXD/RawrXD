OPTION CASEMAP:NONE
EXTERN RemoteCrc32:PROC
EXTERN RemoteUtf16_Validate:PROC
EXTERN RemotePath_IsRelativeSafe:PROC
EXTERN RemoteMulU64:PROC
EXTERN RemoteRange_Validate:PROC
EXTERN RemoteAuthFailure_Record:PROC
EXTERN RemoteFrameId_Accept:PROC
EXTERN RemoteSession_ValidatePayload:PROC
PUBLIC RemoteFinalSelfTest
.data
crcText BYTE '1','2','3','4','5','6','7','8','9'
goodText WORD 'O','K',0
goodPath WORD 'f','o','l','d','e','r','\','f','i','l','e','.','b','i','n',0
badPath WORD '.','.','\','s','e','c','r','e','t',0
.code
RemoteFinalSelfTest PROC
    sub rsp,58h
    lea rcx,crcText
    mov edx,9
    call RemoteCrc32
    cmp eax,0CBF43926h
    jne fst_fail
    lea rcx,goodText
    mov edx,2
    call RemoteUtf16_Validate
    test eax,eax
    jz fst_fail
    lea rcx,goodPath
    call RemotePath_IsRelativeSafe
    test eax,eax
    jz fst_fail
    lea rcx,badPath
    call RemotePath_IsRelativeSafe
    test eax,eax
    jnz fst_fail
    mov rcx,100
    mov rdx,200
    lea r8,[rsp+40h]
    call RemoteMulU64
    test eax,eax
    jz fst_fail
    cmp QWORD PTR [rsp+40h],20000
    jne fst_fail
    mov rcx,90
    mov rdx,10
    mov r8,100
    call RemoteRange_Validate
    test eax,eax
    jz fst_fail
    mov QWORD PTR [rsp+30h],0
    lea rcx,[rsp+30h]
    call RemoteAuthFailure_Record
    cmp eax,0
    jne fst_fail
    mov QWORD PTR [rsp+38h],0
    lea rcx,[rsp+38h]
    mov rdx,1
    call RemoteFrameId_Accept
    test eax,eax
    jz fst_fail
    mov rcx,16777217
    call RemoteSession_ValidatePayload
    test eax,eax
    jnz fst_fail
    mov eax,1
    jmp fst_done
fst_fail:
    xor eax,eax
fst_done:
    add rsp,58h
    ret
RemoteFinalSelfTest ENDP
END
