OPTION CASEMAP:NONE
PUBLIC RemoteClipboard_ValidateSize
MAX_CLIPBOARD_BYTES EQU 1048576
.code
RemoteClipboard_ValidateSize PROC
    xor eax,eax
    cmp rcx,MAX_CLIPBOARD_BYTES
    seta al
    xor eax,1
    ret
RemoteClipboard_ValidateSize ENDP
END
