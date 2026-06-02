OPTION CASEMAP:NONE

INCLUDE d:\arena_alloc.inc

PUBLIC ArenaReserve
PUBLIC ArenaAllocate
PUBLIC ArenaRelease

.data
ArenaShimBuffer db 200000h dup(0)

.code

; rcx = ArenaContext*, rdx = ReserveSize, r8 = InitialCommit, r9 = CommitGranularity
ArenaReserve PROC ArenaCtx:QWORD, ReserveSize:QWORD, InitialCommit:QWORD, CommitGranularity:QWORD
    test rcx, rcx
    jz  reserve_fail

    lea rax, ArenaShimBuffer
    mov qword ptr [rcx + ArenaContext.BaseAddress], rax
    mov qword ptr [rcx + ArenaContext.CurrentOffset], 0
    mov qword ptr [rcx + ArenaContext.TotalCommitted], SIZEOF ArenaShimBuffer
    mov qword ptr [rcx + ArenaContext.ReservedSize], SIZEOF ArenaShimBuffer
    mov qword ptr [rcx + ArenaContext.CommitGranularity], r9
    mov eax, 1
    ret

reserve_fail:
    xor eax, eax
    ret
ArenaReserve ENDP

; rcx = ArenaContext*, rdx = RequestSize, r8 = Alignment
ArenaAllocate PROC ArenaCtx:QWORD, RequestSize:QWORD, Alignment:QWORD
    test rcx, rcx
    jz  alloc_fail

    mov r10, qword ptr [rcx + ArenaContext.BaseAddress]
    test r10, r10
    jz  alloc_fail

    mov r11, qword ptr [rcx + ArenaContext.CurrentOffset]

    mov rax, r8
    test rax, rax
    jnz have_align
    mov rax, 1
have_align:
    dec rax
    add r11, rax
    not rax
    and r11, rax

    mov rax, r11
    add rax, rdx
    jc  alloc_fail

    cmp rax, qword ptr [rcx + ArenaContext.ReservedSize]
    ja  alloc_fail

    mov qword ptr [rcx + ArenaContext.CurrentOffset], rax
    lea rax, [r10 + r11]
    ret

alloc_fail:
    xor rax, rax
    ret
ArenaAllocate ENDP

; rcx = ArenaContext*
ArenaRelease PROC ArenaCtx:QWORD
    test rcx, rcx
    jz  release_fail

    mov qword ptr [rcx + ArenaContext.BaseAddress], 0
    mov qword ptr [rcx + ArenaContext.CurrentOffset], 0
    mov qword ptr [rcx + ArenaContext.TotalCommitted], 0
    mov qword ptr [rcx + ArenaContext.ReservedSize], 0
    mov qword ptr [rcx + ArenaContext.CommitGranularity], 0
    mov eax, 1
    ret

release_fail:
    xor eax, eax
    ret
ArenaRelease ENDP

END
