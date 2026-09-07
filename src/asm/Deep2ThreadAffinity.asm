; Deep2ThreadAffinity.asm — hard thread/process affinity via kernel32
OPTION CASEMAP:NONE
EXTERN SetThreadAffinityMask:PROC
EXTERN SetProcessAffinityMask:PROC
PUBLIC AssertHardThreadAffinity
PUBLIC RestrictOsBackgroundTasks

.code

; RCX=HANDLE thread  RDX=uint64 mask
; RAX=previous mask (0 = fail)
AssertHardThreadAffinity PROC FRAME
    sub rsp, 28h
    .ENDPROLOG
    test rcx, rcx
    jz AffFail
    test rdx, rdx
    jz AffFail
    call SetThreadAffinityMask
    add rsp, 28h
    ret
AffFail:
    xor eax, eax
    add rsp, 28h
    ret
AssertHardThreadAffinity ENDP

; RCX=HANDLE process  RDX=uint64 background mask
; void — applies SetProcessAffinityMask
RestrictOsBackgroundTasks PROC FRAME
    sub rsp, 28h
    .ENDPROLOG
    test rcx, rcx
    jz ResDone
    test rdx, rdx
    jz ResDone
    call SetProcessAffinityMask
ResDone:
    add rsp, 28h
    ret
RestrictOsBackgroundTasks ENDP

END
