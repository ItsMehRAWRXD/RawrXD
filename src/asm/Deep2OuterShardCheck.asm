; Deep2OuterShardCheck.asm — missing indices + completeness flags
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
PUBLIC OuterFinalizeScan
PUBLIC OuterScanFlags

.code
; RCX=scanRec
OuterFinalizeScan PROC
    test rcx, rcx
    jz FS_Done
    mov edx, 1
FS_Loop:
    cmp edx, dword ptr [rcx + OS_EXPECTED]
    ja FS_Done
    lea r8, [rcx + OS_PRESENT]
    mov eax, edx
    dec eax
    cmp byte ptr [r8 + rax], 0
    jne FS_Next
    inc dword ptr [rcx + OS_MISS]
FS_Next:
    inc edx
    jmp FS_Loop
FS_Done:
    ret
OuterFinalizeScan ENDP

; RCX=scanRec  EAX=OUT_F_* bits (complete-set only)
OuterScanFlags PROC
    xor eax, eax
    test rcx, rcx
    jz SF_Done
    or eax, OUT_F_NO_DUP or OUT_F_NO_MISS or OUT_F_HDR_OK or OUT_F_COMPLETE
    mov edx, dword ptr [rcx + OS_DUP]
    test edx, edx
    jz SF_Miss
    and eax, NOT OUT_F_NO_DUP
    and eax, NOT OUT_F_COMPLETE
SF_Miss:
    mov edx, dword ptr [rcx + OS_MISS]
    test edx, edx
    jz SF_Hdr
    and eax, NOT OUT_F_NO_MISS
    and eax, NOT OUT_F_COMPLETE
SF_Hdr:
    mov edx, dword ptr [rcx + OS_HDR_FAIL]
    or edx, dword ptr [rcx + OS_BAD_IDX]
    test edx, edx
    jz SF_Cnt
    and eax, NOT OUT_F_HDR_OK
    and eax, NOT OUT_F_COMPLETE
SF_Cnt:
    mov edx, dword ptr [rcx + OS_FOUND]
    cmp edx, dword ptr [rcx + OS_EXPECTED]
    je SF_Tot
    and eax, not OUT_F_COMPLETE
SF_Tot:
    mov edx, dword ptr [rcx + OS_PARSED_TOTAL]
    cmp edx, dword ptr [rcx + OS_EXPECTED]
    je SF_Done
    and eax, not OUT_F_COMPLETE
SF_Done:
    ret
OuterScanFlags ENDP
END
