; ==============================================================================
; Sovereign_Hooks.asm
; Sovereign Dynamic Hooking & Detour Engine
; Implementation of "Elite" Suite Component #3
; Pure x64 MASM / Zero Dependencies / Zero IAT
; ==============================================================================

option casemap:none
include Sovereign_Common.inc

EXTERN g_ApiTable : SOVEREIGN_API_TABLE
EXTERN Elite_NtProtectVirtualMemory : PROC ; From Sovereign_Syscalls.asm

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_InstallDetour
; Input:  RCX = Target Function Address, RDX = Proxy Function Address
; Output: RAX = Trampoline Address (to call original)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_InstallDetour
Sovereign_InstallDetour PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 48

    mov r12, rcx                ; R12 = Target
    mov r13, rdx                ; R13 = Proxy

    ; 1. Allocate memory for Trampoline (Exec-Read-Write)
    xor rcx, rcx                ; NULL base
    mov rdx, 64                 ; Size
    mov r8, 3000h               ; MEM_COMMIT | MEM_RESERVE
    mov r9, 40h                 ; PAGE_EXECUTE_READWRITE
    call [g_ApiTable.pVirtualAlloc]
    test rax, rax
    jz fail_hook
    
    mov rsi, rax                ; RSI = Trampoline Address
    
    ; 2. Backup original 14 bytes from Target to Trampoline
    mov rdi, rsi
    mov rcx, 14
    mov rsi, r12
    rep movsb                   ; Copy target start
    
    ; 3. Add jump-back to Trampoline (at offset 14)
    ; Opcode: FF 25 00 00 00 00 [Address]
    mov byte ptr [rdi], 0FFh
    mov byte ptr [rdi+1], 25h
    mov dword ptr [rdi+2], 0
    mov rax, r12
    add rax, 14                 ; Jump back to Target + 14
    mov [rdi+6], rax

    ; 4. Prepare Target for patching (Unprotect)
    ; We use Elite_NtProtectVirtualMemory (Direct Syscall) for stealth
    mov rcx, -1                 ; CurrentProcess
    lea rdx, [rsp + 32]         ; Pointer to BaseAddress
    mov [rdx], r12
    lea r8, [rsp + 40]          ; Pointer to Size
    mov qword ptr [r8], 14
    mov r9, 40h                 ; PAGE_EXECUTE_READWRITE
    lea rax, [rsp + 24]         ; OldProtect
    push rax
    call Elite_NtProtectVirtualMemory
    add rsp, 8
    
    ; 5. Write Detour to Target (14 bytes)
    ; Opcode: FF 25 00 00 00 00 [ProxyAddress]
    mov byte ptr [r12], 0FFh
    mov byte ptr [r12+1], 25h
    mov dword ptr [r12+2], 0
    mov [r12+6], r13            ; Proxy address

    ; 6. Restore Protection on Target
    mov rcx, -1
    lea rdx, [rsp + 32]
    mov [rdx], r12
    lea r8, [rsp + 40]
    mov qword ptr [r8], 14
    mov r9d, [rsp + 24]         ; OldProtect
    lea rax, [rsp + 44]         ; Dummy NewOldProtect
    push rax
    call Elite_NtProtectVirtualMemory
    add rsp, 8

    ; Return Trampoline Address in RAX
    mov rax, rsi
    jmp done

fail_hook:
    xor rax, rax

done:
    add rsp, 48
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_InstallDetour ENDP

END
