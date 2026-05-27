; Sovereign_Scheduler_Harden.asm
; x64 MASM — Zero Dependency — PEB Runtime Resolution
; Hardens process/thread priority at latch_4th via native syscall boundary

.data
    ; Resolved function pointers (populated once at engine init)
    fp_SetPriorityClass       DQ 0
    fp_SetThreadPriority      DQ 0
    fp_SetThreadAffinityMask  DQ 0

    ; Export name targets (null-terminated, exact case)
    sz_SetPriorityClass       DB "SetPriorityClass", 0
    sz_SetThreadPriority      DB "SetThreadPriority", 0
    sz_SetThreadAffinityMask  DB "SetThreadAffinityMask", 0

    ; Execution constants
    HIGH_PRIORITY_CLASS       EQU 00000080h
    NORMAL_PRIORITY_CLASS     EQU 00000020h
    THREAD_PRIORITY_TIME_CRITICAL EQU 15
    THREAD_PRIORITY_NORMAL    EQU 0
    ; Cores 8-15 isolated (tune to your 16-core topology)
    NUMA_ISOLATION_MASK       DQ 000000000000FF00h
    ALL_CORES_MASK            DQ 0FFFFFFFFFFFFFFFFh

.code

; -------------------------------------------------------------------
; StrCmpA — Byte-compare two ASCIIZ strings
; Input:  RCX = str1, RDX = str2
; Output: RAX = 1 if equal, 0 if not
; -------------------------------------------------------------------
StrCmpA PROC
    push    rsi
    push    rdi
    mov     rsi, rcx
    mov     rdi, rdx
L_loop:
    mov     al, [rsi]
    mov     dl, [rdi]
    cmp     al, dl
    jne     L_ne
    test    al, al
    jz      L_eq
    inc     rsi
    inc     rdi
    jmp     L_loop
L_ne:
    xor     rax, rax
    jmp     L_done
L_eq:
    mov     rax, 1
L_done:
    pop     rdi
    pop     rsi
    ret
StrCmpA ENDP

; -------------------------------------------------------------------
; ResolveExport — Walk module EAT to resolve function by name
; Input:  RCX = ASCIIZ name, RDX = DllBase
; Output: RAX = function VA, or 0 if not found
; -------------------------------------------------------------------
ResolveExport PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13

    mov     r12, rcx                ; Target name
    mov     rbx, rdx                ; Image base

    mov     eax, [rbx+3Ch]          ; e_lfanew
    add     rax, rbx                ; NT Headers
    mov     r8d, [rax+88h]          ; DataDirectory[0].VA (Export Dir)
    test    r8, r8
    jz      L_not_found
    add     r8, rbx                 ; R8 = Export Directory VA

    mov     r9d, [r8+20h]           ; AddressOfNames RVA
    add     r9, rbx                 ; R9 = Name pointer table
    mov     r10d, [r8+24h]          ; AddressOfNameOrdinals RVA
    add     r10, rbx                ; R10 = Ordinal table
    mov     r11d, [r8+1Ch]          ; AddressOfFunctions RVA
    add     r11, rbx                ; R11 = Function table
    mov     r13d, [r8+14h]          ; NumberOfNames

    xor     rsi, rsi                ; Name index

L_next_name:
    cmp     rsi, r13
    jae     L_not_found
    mov     edi, [r9+rsi*4]         ; Name RVA
    add     rdi, rbx                ; Name VA
    mov     rcx, r12
    mov     rdx, rdi
    call    StrCmpA
    test    rax, rax
    jnz     L_found
    inc     rsi
    jmp     L_next_name

L_found:
    movzx   eax, word ptr [r10+rsi*2]   ; Ordinal
    mov     eax, [r11+rax*4]            ; Function RVA
    add     rax, rbx
    jmp     L_done

L_not_found:
    xor     rax, rax

L_done:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
ResolveExport ENDP

; -------------------------------------------------------------------
; FindKernel32 — Walk InMemoryOrderModuleList, validate by export
; Output: RAX = kernel32 DllBase, or 0
; -------------------------------------------------------------------
FindKernel32 PROC
    push    rbx
    push    rsi
    push    rdi

    mov     rax, gs:[60h]           ; TEB->PEB
    mov     rax, [rax+18h]          ; PEB->Ldr
    lea     rsi, [rax+20h]          ; &Ldr->InMemoryOrderModuleList (head)
    mov     rbx, [rsi]              ; Flink -> first entry

L_next_mod:
    cmp     rbx, rsi                ; Looped back to head?
    je      L_not_found

    mov     rcx, [rbx+20h]          ; DllBase (offset 0x30 - 0x10 = 0x20)
    test    rcx, rcx
    jz      L_skip

    ; Validate: does this module export SetPriorityClass?
    mov     rdx, rcx
    lea     rcx, [sz_SetPriorityClass]
    call    ResolveExport
    test    rax, rax
    jnz     L_found

L_skip:
    mov     rbx, [rbx]              ; Next Flink
    jmp     L_next_mod

L_found:
    mov     rax, [rbx+20h]          ; Return DllBase
    jmp     L_done

L_not_found:
    xor     rax, rax

L_done:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
FindKernel32 ENDP

; -------------------------------------------------------------------
; Sovereign_ResolveSchedulerAPIs
; Call once at engine startup. Populates fp_* table via PEB.
; -------------------------------------------------------------------
Sovereign_ResolveSchedulerAPIs PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    call    FindKernel32
    test    rax, rax
    jz      L_fail
    mov     rbx, rax                ; RBX = kernel32 base

    lea     rcx, [sz_SetPriorityClass]
    mov     rdx, rbx
    call    ResolveExport
    mov     [fp_SetPriorityClass], rax

    lea     rcx, [sz_SetThreadPriority]
    mov     rdx, rbx
    call    ResolveExport
    mov     [fp_SetThreadPriority], rax

    lea     rcx, [sz_SetThreadAffinityMask]
    mov     rdx, rbx
    call    ResolveExport
    mov     [fp_SetThreadAffinityMask], rax

L_fail:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Sovereign_ResolveSchedulerAPIs ENDP

; -------------------------------------------------------------------
; Sovereign_Scheduler_Harden
; Asserts at latch_4th. Seizes scheduler control.
; -------------------------------------------------------------------
Sovereign_Scheduler_Harden PROC
    sub     rsp, 28h

    mov     rax, [fp_SetPriorityClass]
    test    rax, rax
    jz      L_done

    ; Process -> HIGH_PRIORITY_CLASS (Pseudo-handle -1)
    mov     rcx, -1
    mov     edx, HIGH_PRIORITY_CLASS
    call    rax

    ; Thread -> TIME_CRITICAL (Pseudo-handle -2)
    mov     rax, [fp_SetThreadPriority]
    test    rax, rax
    jz      L_done
    mov     rcx, -2
    mov     edx, THREAD_PRIORITY_TIME_CRITICAL
    call    rax

    ; Isolate to cores 8-15 (NUMA hardening)
    mov     rax, [fp_SetThreadAffinityMask]
    test    rax, rax
    jz      L_done
    mov     rcx, -2
    mov     rdx, NUMA_ISOLATION_MASK
    call    rax

L_done:
    add     rsp, 28h
    ret
Sovereign_Scheduler_Harden ENDP

; -------------------------------------------------------------------
; Sovereign_Scheduler_Release
; Drops priority when gravity collapses or engine shuts down.
; -------------------------------------------------------------------
Sovereign_Scheduler_Release PROC
    sub     rsp, 28h

    mov     rax, [fp_SetPriorityClass]
    test    rax, rax
    jz      L_done

    mov     rcx, -1
    mov     edx, NORMAL_PRIORITY_CLASS
    call    rax

    mov     rax, [fp_SetThreadPriority]
    test    rax, rax
    jz      L_done
    mov     rcx, -2
    xor     edx, edx                ; THREAD_PRIORITY_NORMAL
    call    rax

    mov     rax, [fp_SetThreadAffinityMask]
    test    rax, rax
    jz      L_done
    mov     rcx, -2
    mov     rdx, ALL_CORES_MASK
    call    rax

L_done:
    add     rsp, 28h
    ret
Sovereign_Scheduler_Release ENDP

PUBLIC  Sovereign_ResolveSchedulerAPIs
PUBLIC  Sovereign_Scheduler_Harden
PUBLIC  Sovereign_Scheduler_Release

END