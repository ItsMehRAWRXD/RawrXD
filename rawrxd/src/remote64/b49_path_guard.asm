OPTION CASEMAP:NONE
PUBLIC RemotePath_IsRelativeSafe
.code
RemotePath_IsRelativeSafe PROC
    ; rcx=UTF16 path. rejects empty, absolute, drive, UNC and ".." component.
    mov ax,[rcx]
    test ax,ax
    jz pg_bad
    cmp ax,'\'
    je pg_bad
    cmp ax,'/'
    je pg_bad
    mov dx,[rcx+2]
    cmp dx,':'
    je pg_bad
    mov r8,rcx
pg_scan:
    mov ax,[r8]
    test ax,ax
    jz pg_ok
    cmp ax,'.'
    jne pg_next
    cmp WORD PTR [r8+2],'.'
    jne pg_next
    ; component boundary before and after
    cmp r8,rcx
    je pg_after
    mov dx,[r8-2]
    cmp dx,'\'
    je pg_after
    cmp dx,'/'
    jne pg_next
pg_after:
    mov dx,[r8+4]
    test dx,dx
    jz pg_bad
    cmp dx,'\'
    je pg_bad
    cmp dx,'/'
    je pg_bad
pg_next:
    add r8,2
    jmp pg_scan
pg_ok:
    mov eax,1
    ret
pg_bad:
    xor eax,eax
    ret
RemotePath_IsRelativeSafe ENDP
END
