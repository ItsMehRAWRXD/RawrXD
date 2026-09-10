; Sentinel_Knowledge_Arena.asm — R13 8GB canvas bounds (Sentinel only)
; SHADOW harness draft — not axiom identity (TRIAD_REVOLVER_GGUF_HOLD_001)
; Arena = [R13, R13 + ARENA_SIZE). Walker must call before tensor touch.
OPTION CASEMAP:NONE
INCLUDE ksamd64.inc

ARENA_SIZE      EQU 200000000h          ; 8GB
GUARD_PAGESZ    EQU 1000h               ; 4KB
PAGE_READWRITE  EQU 04h
PAGE_GUARD      EQU 100h
PAGE_RW_GUARD   EQU (PAGE_READWRITE OR PAGE_GUARD)

EXTERN VirtualProtect:PROC

PUBLIC Sentinel_InitArena
PUBLIC Sentinel_ContainsRange
PUBLIC Sentinel_InstallTailGuard

.data?
align 8
g_arena_base    dq ?
g_arena_end     dq ?                    ; exclusive end = base+8GB
g_old_prot      dd ?
            align 8

.code

; RCX=base (pinned into R13 by caller), RDX unused
; OUT: RAX=1 ok / 0 fail; R13=base on success
Sentinel_InitArena PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    test rcx, rcx
    jz init_fail
    mov r13, rcx
    mov qword ptr [g_arena_base], rcx
    mov rax, rcx
    add rax, ARENA_SIZE
    jc init_fail                        ; wrap
    mov qword ptr [g_arena_end], rax
    mov eax, 1
    pop rbp
    ret
init_fail:
    xor eax, eax
    pop rbp
    ret
Sentinel_InitArena ENDP

; RCX=ptr, RDX=nbytes — range must lie in [base,end)
; OUT: RAX=1 inside / 0 breach (incl. wrap)
Sentinel_ContainsRange PROC
    mov r8, qword ptr [g_arena_base]
    mov r9, qword ptr [g_arena_end]
    test rdx, rdx
    jz range_bad
    mov rax, rcx
    add rax, rdx
    jc range_bad
    cmp rcx, r8
    jb range_bad
    cmp rax, r9
    ja range_bad
    mov eax, 1
    ret
range_bad:
    xor eax, eax
    ret
Sentinel_ContainsRange ENDP

; PAGE_GUARD on final 4KB of arena (overflow tripwire)
; OUT: RAX=1 ok / 0 VirtualProtect fail
Sentinel_InstallTailGuard PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 30h
    .allocstack 30h
    .endprolog
    mov rcx, qword ptr [g_arena_end]
    sub rcx, GUARD_PAGESZ               ; last page
    mov rdx, GUARD_PAGESZ
    mov r8d, PAGE_RW_GUARD
    lea r9, qword ptr [g_old_prot]
    call VirtualProtect
    test eax, eax
    jz guard_fail
    mov eax, 1
    add rsp, 30h
    pop rbp
    ret
guard_fail:
    xor eax, eax
    add rsp, 30h
    pop rbp
    ret
Sentinel_InstallTailGuard ENDP

END
