;==============================================================================
; RAWRXD_SCHEDULER.asm
; LANE D: SOVEREIGN GOLDILOCKS SCHEDULER
; Real-time thread priority lease, core affinity pinning, RDTSC telemetry.
; Zero-CRT, compact, no scaffolding.
;==============================================================================
OPTION CASEMAP:NONE

.CODE

;------------------------------------------------------------------------------
; RawrSched_EnterLease(pCtx:rcx, targetPriority:edx, targetAffinity:r8)
; Captures current thread state, escalates priority, optionally pins affinity.
; pCtx points to: { DWORD origPri; DWORD pad; QWORD origAffinity; QWORD startTSC;
;                   QWORD accumCycles; DWORD leaseActive; DWORD pad2; }
;------------------------------------------------------------------------------
RawrSched_EnterLease PROC
    test rcx, rcx
    jz @@done

    push rbx
    push rdi
    mov rbx, rcx
    mov edi, edx          ; targetPriority

    ; Get current thread pseudo-handle
    call GetCurrentThread
    mov r9, rax           ; r9 = thread handle

    ; Save original priority
    mov rcx, r9
    call GetThreadPriority
    mov [rbx], eax        ; origPri

    ; Apply new priority
    mov rcx, r9
    mov edx, edi
    call SetThreadPriority

    ; Handle affinity pinning if targetAffinity != 0
    test r8, r8
    jz @@skip_affinity
    mov rcx, r9
    mov rdx, r8
    call SetThreadAffinityMask
    mov [rbx+8], rax      ; origAffinity
@@skip_affinity:

    ; Mark lease active and capture start TSC
    mov dword ptr [rbx+24], 1   ; leaseActive
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx+16], rax     ; startTSC

    pop rdi
    pop rbx
@@done:
    ret
RawrSched_EnterLease ENDP

;------------------------------------------------------------------------------
; RawrSched_ExitLease(pCtx:rcx)
; Restores original priority/affinity, accumulates elapsed cycles.
;------------------------------------------------------------------------------
RawrSched_ExitLease PROC
    test rcx, rcx
    jz @@done

    push rbx
    mov rbx, rcx

    ; Guard: only exit if lease is active
    cmp dword ptr [rbx+24], 1
    jne @@exit_early

    ; Capture end TSC and compute delta
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r10, [rbx+16]     ; startTSC
    sub rax, r10
    add [rbx+32], rax     ; accumCycles += delta

    ; Get current thread
    call GetCurrentThread
    mov r9, rax

    ; Restore original affinity if non-zero
    mov rdx, [rbx+8]
    test rdx, rdx
    jz @@skip_affinity_restore
    mov rcx, r9
    call SetThreadAffinityMask
@@skip_affinity_restore:

    ; Restore original priority
    mov rcx, r9
    movsx rdx, dword ptr [rbx]
    call SetThreadPriority

    ; Clear lease active
    mov dword ptr [rbx+24], 0

@@exit_early:
    pop rbx
@@done:
    ret
RawrSched_ExitLease ENDP

;------------------------------------------------------------------------------
; RawrSched_ReadCycles() -> RAX
; Returns 64-bit TSC. No arguments, no side effects.
;------------------------------------------------------------------------------
RawrSched_ReadCycles PROC
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
RawrSched_ReadCycles ENDP

END
