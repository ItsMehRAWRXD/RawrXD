; Deep2OuterShardApply.asm — record one parsed split shard
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN Deep2Outer_CheckGgufHeader:PROC
PUBLIC OuterApplyShard

.code
; RCX=scanRec EDX=index R8D=total R9=fullpath
OuterApplyShard PROC
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    test edx, edx
    jz AP_Bad
    cmp edx, 32
    ja AP_Bad
    cmp edx, dword ptr [rbx + OS_EXPECTED]
    ja AP_Bad
    test r8d, r8d
    jz AP_Bad
    mov eax, dword ptr [rbx + OS_PARSED_TOTAL]
    test eax, eax
    jnz AP_Tot
    mov dword ptr [rbx + OS_PARSED_TOTAL], r8d
    jmp AP_Mark
AP_Tot:
    cmp eax, r8d
    je AP_Mark
AP_Bad:
    inc dword ptr [rbx + OS_BAD_IDX]
    jmp AP_Done
AP_Mark:
    lea r10, [rbx + OS_PRESENT]
    mov eax, edx
    dec eax
    cmp byte ptr [r10 + rax], 0
    je AP_New
    inc dword ptr [rbx + OS_DUP]
    jmp AP_Hdr
AP_New:
    mov byte ptr [r10 + rax], 1
    inc dword ptr [rbx + OS_FOUND]
AP_Hdr:
    mov rcx, r9
    call Deep2Outer_CheckGgufHeader
    test eax, eax
    jnz AP_Done
    inc dword ptr [rbx + OS_HDR_FAIL]
AP_Done:
    add rsp, 20h
    pop rbx
    ret
OuterApplyShard ENDP
END
