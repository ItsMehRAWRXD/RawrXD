option casemap:none
include ..\include\deep2_nodep.inc
PUBLIC Deep2HotsetLookup
.code
; rcx=entries, rdx=count, r8=region_id, r9=generation
; returns index+1 on exact HOT hit, 0 on miss. No family heuristic, no eviction policy.
Deep2HotsetLookup PROC
    test rcx, rcx
    jz hs_miss
    xor rax, rax
hs_loop:
    cmp rax, rdx
    jae hs_miss
    mov r10, rax
    imul r10, D2_HOT_SIZE
    cmp [rcx+r10+D2_HOT_REGION_ID], r8
    jne hs_next
    cmp [rcx+r10+D2_HOT_GENERATION], r9
    jne hs_next
    cmp qword ptr [rcx+r10+D2_HOT_STATE], D2_RES_HOT
    jne hs_next
    inc rax
    ret
hs_next:
    inc rax
    jmp hs_loop
hs_miss:
    xor eax, eax
    ret
Deep2HotsetLookup ENDP
END
