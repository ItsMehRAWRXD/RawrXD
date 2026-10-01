OPTION CASEMAP:NONE
include remote.inc
EXTERN CreateFileW:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
PUBLIC RemoteFile_OpenRead
PUBLIC RemoteFile_OpenWrite
PUBLIC RemoteFile_ReadChunk
PUBLIC RemoteFile_WriteChunk
PUBLIC RemoteFile_Close

GENERIC_READ EQU 80000000h
GENERIC_WRITE EQU 40000000h
FILE_SHARE_READ EQU 1
OPEN_EXISTING EQU 3
CREATE_ALWAYS EQU 2
FILE_ATTRIBUTE_NORMAL EQU 80h
INVALID_HANDLE_VALUE EQU -1

.code
RemoteFile_OpenRead PROC
    ; rcx=absolute path
    sub rsp,38h
    mov rdx,GENERIC_READ
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov QWORD PTR [rsp+20h],OPEN_EXISTING
    mov QWORD PTR [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+30h],0
    call CreateFileW
    add rsp,38h
    ret
RemoteFile_OpenRead ENDP

RemoteFile_OpenWrite PROC
    ; rcx=host-approved destination path
    sub rsp,38h
    mov rdx,GENERIC_WRITE
    xor r8d,r8d
    xor r9d,r9d
    mov QWORD PTR [rsp+20h],CREATE_ALWAYS
    mov QWORD PTR [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+30h],0
    call CreateFileW
    add rsp,38h
    ret
RemoteFile_OpenWrite ENDP

RemoteFile_ReadChunk PROC
    ; rcx=h, rdx=dst, r8d=capacity, r9=bytesRead*
    sub rsp,28h
    mov QWORD PTR [rsp+20h],0
    call ReadFile
    add rsp,28h
    ret
RemoteFile_ReadChunk ENDP

RemoteFile_WriteChunk PROC
    ; rcx=h, rdx=src, r8d=len, r9=bytesWritten*
    sub rsp,28h
    mov QWORD PTR [rsp+20h],0
    call WriteFile
    add rsp,28h
    ret
RemoteFile_WriteChunk ENDP

RemoteFile_Close PROC
    sub rsp,28h
    call CloseHandle
    add rsp,28h
    ret
RemoteFile_Close ENDP
END
