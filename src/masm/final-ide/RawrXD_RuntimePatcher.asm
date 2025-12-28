; RawrXD_RuntimePatcher.asm
; Hot-patches running code with atomicity and rollback

include masm_hotpatch.inc

.data
g_patchMutex QWORD 0
g_patchLog BYTE 256 DUP(0)

.const
PAGE_EXECUTE_READWRITE EQU 040h
PATCH_SIZE EQU 15              ; Max instruction size for patch

.code

EXTERN asm_mutex_create:PROC
EXTERN asm_mutex_lock:PROC
EXTERN asm_mutex_unlock:PROC

; Patches a function pointer at runtime
; rcx = targetAddress (QWORD*), rdx = newFunctionPtr
RawrXD_AtomicPatch PROC FRAME
    push rbx
    push rbp
    .pushreg rbx
    .pushreg rbp
    sub rsp, 48
    .allocstack 56
    .endprolog
    
    mov rbx, rcx                 ; targetAddress
    mov rbp, rdx                 ; newFunctionPtr
    
    ; Acquire patch mutex (reentrant lock)
    call RawrXD_AcquirePatchMutex
    
    ; Change page protection
    mov rcx, rbx
    mov rdx, 8                   ; Size of pointer
    mov r8, PAGE_EXECUTE_READWRITE
    lea r9, [rsp+32]             ; OldProtect
    call VirtualProtect
    
    ; Atomic write (8-byte aligned, atomic on x64)
    mov rax, [rbp]
    xchg QWORD PTR [rbx], rax    ; Atomic swap
    
    ; Restore protection
    mov rcx, rbx
    mov rdx, 8
    mov r8d, [rsp+32]            ; OldProtect
    mov rax, r8
    mov r8, rax
    lea r9, [rsp+32]
    call VirtualProtect
    
    ; Flush instruction cache
    call GetCurrentProcess
    mov rcx, rax
    mov rdx, rbx
    mov r8, 8
    call FlushInstructionCache
    
    ; Release mutex
    call RawrXD_ReleasePatchMutex
    
    ; Log patch
    call RawrXD_LogPatchEvent
    
    xor eax, eax
    add rsp, 48
    pop rbp
    pop rbx
    ret
RawrXD_AtomicPatch ENDP

; Rollback last patch (for error recovery)
RawrXD_AtomicRollback PROC FRAME
    .endprolog
    
    ; Stub for now
ROLLBACK_NONE:
    ret
RawrXD_AtomicRollback ENDP

; Mutex for patch safety
RawrXD_AcquirePatchMutex PROC
    push rbx
    sub rsp, 32
    
    cmp g_patchMutex, 0
    jne acquire_lock
    
    ; Create mutex if not exists
    call asm_mutex_create
    mov g_patchMutex, rax
    
acquire_lock:
    mov rcx, g_patchMutex
    call asm_mutex_lock
    
    add rsp, 32
    pop rbx
    ret
RawrXD_AcquirePatchMutex ENDP

RawrXD_ReleasePatchMutex PROC
    push rbx
    sub rsp, 32
    
    cmp g_patchMutex, 0
    je no_mutex_release
    
    mov rcx, g_patchMutex
    call asm_mutex_unlock
    
no_mutex_release:
    add rsp, 32
    pop rbx
    ret
RawrXD_ReleasePatchMutex ENDP

; Log patch to IDE console
RawrXD_LogPatchEvent PROC
    lea rcx, g_patchLog
    call OutputDebugStringA
    ret
RawrXD_LogPatchEvent ENDP

END
