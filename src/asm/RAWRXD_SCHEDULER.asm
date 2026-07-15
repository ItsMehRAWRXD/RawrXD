;==============================================================================
; RAWRXD_SCHEDULER.asm
; LANE D: SOVEREIGN GOLDILOCKS SCHEDULER (Fixed Win64 ABI Edition)
; Zero-CRT, compact, fully aligned real-time scheduling core.
; Win64 ABI Compliant: Non-volatile preservation, shadow space, stack alignment.
;==============================================================================
OPTION CASEMAP:NONE

; External Win32 Kernel Entry Points
EXTERN GetCurrentThread      : PROC
EXTERN SetThreadPriority     : PROC
EXTERN GetThreadPriority     : PROC
EXTERN SetThreadAffinityMask : PROC

.CODE

;------------------------------------------------------------------------------
; RawrSched_EnterLease(pCtx:rcx, targetPriority:edx, targetAffinity:r8)
; Context Struct Layout:
;   +0  : DWORD origPri
;   +4  : DWORD pad
;   +8  : QWORD origAffinity
;   +16 : QWORD startTSC
;   +24 : DWORD leaseActive
;   +28 : DWORD pad2
;   +32 : QWORD accumCycles
;------------------------------------------------------------------------------
RawrSched_EnterLease PROC
    test rcx, rcx
    jz @@done

    ; --- Win64 Stack Frame Setup & Non-Volatile Preservation ---
    push rbx
    push rdi
    push rsi
    push r12
    ; Stack Accounting: 4 pushes = 32 bytes. Entry was (16n + 8). 
    ; Current RSP = (16n + 8 - 32) = (16n - 24).
    ; We allocate 40 bytes: 32 bytes shadow space + 8 bytes alignment padding.
    ; New RSP = (16n - 64), perfectly 16-byte aligned.
    sub rsp, 40

    ; --- Isolate Input Parameters from Volatile Clobbering ---
    mov rbx, rcx            ; rbx = pCtx
    mov edi, edx            ; edi = targetPriority
    mov r12, r8             ; r12 = targetAffinity (Safe from API wipes)

    ; 1. Acquire secure Thread Handle
    call GetCurrentThread
    mov rsi, rax            ; rsi = Thread Handle (Preserved across calls)

    ; 2. Extract and log original thread state
    mov rcx, rsi
    call GetThreadPriority
    mov [rbx], eax          ; Store origPri

    ; 3. Escalate priority state
    mov rcx, rsi
    mov edx, edi
    call SetThreadPriority

    ; 4. Conditionally enforce CCX Hardware Core Affinity Lock
    test r12, r12
    jz @@skip_affinity
    
    mov rcx, rsi
    mov rdx, r12
    call SetThreadAffinityMask
    mov [rbx+8], rax        ; Store returned origAffinity
@@skip_affinity:

    ; 5. Raise Active Lease Flag and sample performance timestamp
    mov dword ptr [rbx+24], 1   ; leaseActive = 1
    rdtsc                       ; EDX:EAX = TSC
    shl rdx, 32
    or rax, rdx
    mov [rbx+16], rax           ; Store startTSC

    ; --- Stack Clean Up & Frame Destruction ---
    add rsp, 40
    pop r12
    pop rsi
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

    ; --- Stack Frame Setup & Alignment ---
    push rbx
    push rsi
    ; 2 pushes = 16 bytes. RSP = (16n - 8). 
    ; Allocate 40 bytes (32 shadow + 8 pad). New RSP = (16n - 48), aligned.
    sub rsp, 40
    
    mov rbx, rcx            ; rbx = pCtx

    ; Guard: Verify structural context state before modification
    cmp dword ptr [rbx+24], 1
    jne @@exit_early

    ; 1. Calculate and update high-precision execution cycle tracking
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r10, [rbx+16]       ; r10 = startTSC
    sub rax, r10            ; rax = delta execution cycles
    add [rbx+32], rax       ; accumCycles += delta

    ; 2. Query Thread Context
    call GetCurrentThread
    mov rsi, rax            ; rsi = Thread Handle

    ; 3. Revert Core Affinity Mask
    mov rdx, [rbx+8]        ; rdx = origAffinity
    test rdx, rdx
    jz @@skip_affinity_restore
    
    mov rcx, rsi
    call SetThreadAffinityMask
@@skip_affinity_restore:

    ; 4. Revert Priority Level 
    mov rcx, rsi
    movsxd rdx, dword ptr [rbx] ; rdx = origPri (Sign-extended)
    call SetThreadPriority

    ; 5. Relinquish lease ownership cleanly
    mov dword ptr [rbx+24], 0

@@exit_early:
    add rsp, 40
    pop rsi
    pop rbx
@@done:
    ret
RawrSched_ExitLease ENDP

;------------------------------------------------------------------------------
; RawrSched_ReadCycles() -> RAX
; Pure, non-destructive low-overhead hardware telemetry tap.
;------------------------------------------------------------------------------
RawrSched_ReadCycles PROC
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
RawrSched_ReadCycles ENDP

END
