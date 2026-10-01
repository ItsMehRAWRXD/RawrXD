OPTION CASEMAP:NONE
PUBLIC RemoteBandwidth_Update
.code
RemoteBandwidth_Update PROC
    ; rcx=state {emaBps qword}, rdx=bytes, r8=elapsed usec
    test r8,r8
    jz bw_done
    mov rax,rdx
    mov r9,1000000
    mul r9
    div r8
    mov r9,[rcx]
    test r9,r9
    jz bw_set
    ; EMA = (7*old + sample)/8
    imul r9,7
    add rax,r9
    shr rax,3
bw_set:
    mov [rcx],rax
bw_done:
    ret
RemoteBandwidth_Update ENDP
END
