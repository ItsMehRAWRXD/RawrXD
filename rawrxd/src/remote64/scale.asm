OPTION CASEMAP:NONE
PUBLIC RemoteScale_MapPoint
.code
RemoteScale_MapPoint PROC
    ; rcx -> {srcW,srcH,dstW,dstH,x,y}; outputs x,y host coords
    mov eax,[rcx+16]
    cdq
    imul rax,QWORD PTR [rcx+0] ; low dword srcW sufficient after division
    mov r8d,[rcx+8]
    test r8d,r8d
    jz sm_fail
    xor edx,edx
    div r8
    mov [rcx+16],eax
    mov eax,[rcx+20]
    mov r8d,[rcx+4]
    imul rax,r8
    mov r8d,[rcx+12]
    test r8d,r8d
    jz sm_fail
    xor edx,edx
    div r8
    mov [rcx+20],eax
    mov eax,1
    ret
sm_fail:
    xor eax,eax
    ret
RemoteScale_MapPoint ENDP
END
