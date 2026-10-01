OPTION CASEMAP:NONE
PUBLIC RemoteFile_ValidateChunk
MAX_FILE_CHUNK EQU 1048576
.code
RemoteFile_ValidateChunk PROC
    xor eax,eax
    test rcx,rcx
    jz @F
    cmp rcx,MAX_FILE_CHUNK
    ja @F
    mov eax,1
@@: ret
RemoteFile_ValidateChunk ENDP
END
