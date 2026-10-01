OPTION CASEMAP:NONE
PUBLIC RemoteDamage_MergeRect
.code
RemoteDamage_MergeRect PROC
    ; rcx={l,t,r,b}, rdx={l,t,r,b}; expands rcx to union.
    mov eax,[rdx]
    cmp eax,[rcx]
    jge @F
    mov [rcx],eax
@@: mov eax,[rdx+4]
    cmp eax,[rcx+4]
    jge @F
    mov [rcx+4],eax
@@: mov eax,[rdx+8]
    cmp eax,[rcx+8]
    jle @F
    mov [rcx+8],eax
@@: mov eax,[rdx+12]
    cmp eax,[rcx+12]
    jle @F
    mov [rcx+12],eax
@@: mov eax,1
    ret
RemoteDamage_MergeRect ENDP
END
