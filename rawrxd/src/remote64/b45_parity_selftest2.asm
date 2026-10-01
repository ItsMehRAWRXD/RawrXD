OPTION CASEMAP:NONE
EXTERN RemoteSequence_Accept:PROC
EXTERN RemoteSession_ValidatePayload:PROC
EXTERN RemoteClipboard_ValidateSize:PROC
EXTERN RemoteFile_ValidateChunk:PROC
EXTERN RemoteHealth_Classify:PROC
PUBLIC RemoteParitySelfTest2
.code
RemoteParitySelfTest2 PROC
    sub rsp,38h
    mov QWORD PTR [rsp+28h],5
    lea rcx,[rsp+28h]
    mov rdx,6
    call RemoteSequence_Accept
    test eax,eax
    jz fail
    lea rcx,[rsp+28h]
    mov rdx,6
    call RemoteSequence_Accept
    test eax,eax
    jnz fail
    mov rcx,16777216
    call RemoteSession_ValidatePayload
    test eax,eax
    jz fail
    mov rcx,1048577
    call RemoteClipboard_ValidateSize
    test eax,eax
    jnz fail
    mov rcx,1048576
    call RemoteFile_ValidateChunk
    test eax,eax
    jz fail
    mov rcx,0
    mov rdx,16000
    call RemoteHealth_Classify
    cmp eax,2
    jne fail
    mov eax,1
    jmp done
fail:
    xor eax,eax
done:
    add rsp,38h
    ret
RemoteParitySelfTest2 ENDP
END
