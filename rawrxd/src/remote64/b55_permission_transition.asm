OPTION CASEMAP:NONE
PUBLIC RemotePermission_Transition
.code
; rcx=current mask, rdx=requested mask, r8=locallyApproved mask
RemotePermission_Transition PROC
    ; Never grant anything not locally approved.
    mov rax,rdx
    and rax,r8
    ; VIEW bit must remain set if session exists.
    or rax,1
    ret
RemotePermission_Transition ENDP
END
