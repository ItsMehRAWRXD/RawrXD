; Sovereign_Hooking.asm - Trampoline Hooking Architecture
; Implements invisible API redirection and behavior modification.

include Sovereign_Common.inc

.code

; ------------------------------------------------------------------------------
; Sovereign_Install_Hook
; RCX = Pointer to SOVEREIGN_HOOK descriptor
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Install_Hook
Sovereign_Install_Hook PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 48             ; Shadow space + locals

    mov r12, rcx            ; R12 = Hook Descriptor

    ; 1. Unlocking: Protect Target Memory (RWX)
    mov rcx, -1             ; CurrentProcess
    lea rdx, [r12 + SOVEREIGN_HOOK.pTarget] ; Address of pTarget pointer
    mov rdx, [rdx]          ; Target VA
    
    ; Setup locals for NtProtectVirtualMemory
    mov qword ptr [rsp + 40], 14 ; RegionSize (Need to pass address)
    lea r8, [rsp + 40]      ; R8 = &RegionSize
    mov r9, 40h             ; PAGE_EXECUTE_READWRITE
    lea rax, [rsp + 32]     ; &OldProtect
    mov [rsp + 20h], rax    ; 5th param (x64 ABI: [rsp+20] is first stack param)
    
    EXTERN Elite_NtProtectVirtualMemory : PROC
    mov rcx, -1             ; ProcessHandle
    mov rdx, r12            ; RDX = &BaseAddress (Wait, we need to pass address of pointer)
    lea rdx, [r12 + SOVEREIGN_HOOK.pTarget]
    ; Re-setup R8, R9 correctly for Elite_NtProtectVirtualMemory
    ; NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, NewProtect, &OldProtect)
    call Elite_NtProtectVirtualMemory
    
    test eax, eax
    jnz @error

    ; 2. Prologue Restoration: Copy original bytes to save area AND Trampoline
    mov rsi, [r12 + SOVEREIGN_HOOK.pTarget]
    lea rdi, [r12 + SOVEREIGN_HOOK.OriginalBytes]
    mov rcx, 14
    rep movsb

    ; 3. The Jump: Overwrite target with Absolute Jmp
    ; ff 25 00 00 00 00 [64-bit address]
    mov rdi, [r12 + SOVEREIGN_HOOK.pTarget]
    mov byte ptr [rdi], 0FFh
    mov byte ptr [rdi + 1], 25h
    mov dword ptr [rdi + 2], 0
    mov rax, [r12 + SOVEREIGN_HOOK.pHandler]
    mov [rdi + 6], rax

    ; 4. Prepare Trampoline (Original Bytes + Jmp back to target+14)
    mov rdi, [r12 + SOVEREIGN_HOOK.pTrampoline]
    test rdi, rdi
    jz @skip_trampoline
    
    lea rsi, [r12 + SOVEREIGN_HOOK.OriginalBytes]
    mov rcx, 14
    rep movsb
    
    ; Jmp back (Target + 14)
    mov byte ptr [rdi], 0FFh
    mov byte ptr [rdi + 1], 25h
    mov dword ptr [rdi + 2], 0
    mov rax, [r12 + SOVEREIGN_HOOK.pTarget]
    add rax, 14
    mov [rdi + 6], rax

@skip_trampoline:
    mov [r12 + SOVEREIGN_HOOK.Active], 1
    xor rax, rax            ; Success
    jmp @done

@error:
    mov rax, -1
@done:
    add rsp, 48
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Install_Hook ENDP

END
