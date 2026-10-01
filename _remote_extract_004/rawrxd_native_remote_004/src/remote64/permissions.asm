OPTION CASEMAP:NONE
PUBLIC RemotePermission_Check
PERM_VIEW EQU 1
PERM_MOUSE EQU 2
PERM_KEYBOARD EQU 4
PERM_CLIPBOARD EQU 8
PERM_FILES EQU 16
.code
RemotePermission_Check PROC
    ; ecx=granted mask, edx=requested mask
    mov eax,ecx
    and eax,edx
    cmp eax,edx
    sete al
    movzx eax,al
    ret
RemotePermission_Check ENDP
END
