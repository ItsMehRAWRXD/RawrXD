; ==============================================================================
; Sovereign_JIT_Elite_Core.asm
; Logic: Universal Syscall Dispatcher & W^X Memory Lifecycle
; ==============================================================================

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Syscall_Invoke
; Input: RCX = Syscall ID, RDX = Arg1, R8 = Arg2, R9 = Arg3, [RSP+40] = Arg4+
; Logic: Universal gateway for all NT syscalls.
; Note: Windows Syscall Convention uses R10 for Arg1, RAX for ID.
; ------------------------------------------------------------------------------
PUBLIC Syscall_Invoke
Syscall_Invoke PROC
    mov rax, rcx          ; Syscall ID -> RAX
    mov r10, rdx          ; Arg1 (RCX) -> R10 (required by syscall instruction)
    
    ; Shift args to kernel expectation (RDX, R8, R9 are already in place for Args 2-4)
    ; But Arg4 in user-mode calling convention is R9.
    ; Arg5 in user-mode is [rsp+40].
    ; The kernel expects Arg4 in R9, Arg5 on stack.
    ; This dispatcher assumes the caller has placed Arg1 in RDX, Arg2 in R8, Arg3 in R9, Arg4 on stack...
    ; To keep it simple and elite, let's assume specific input mapping:
    ; EAX = ID, R10 = Arg1, RDX = Arg2, R8 = Arg3, R9 = Arg4.
    
    syscall
    ret
Syscall_Invoke ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: JIT_Lifecycle_Transition
; Logic: The W^X State Machine (Reserve -> RW -> RX -> Execute)
;        Uses NtProtectVirtualMemory (commonly syscall 0x50 on Win10/11)
; ------------------------------------------------------------------------------
PUBLIC JIT_Lifecycle_Transition
JIT_Lifecycle_Transition PROC
    ; Arguments: RCX = BaseAddr, RDX = Size, R8 = NewProtect (0x20 = RX)
    ; Returns: RAX = NTSTATUS
    sub rsp, 48
    
    ; NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
    ; Syscall ID 0x50
    
    mov [rsp + 40], r8    ; NewProtect (Arg 4 - Shadow Space Offset)
    lea rax, [rsp + 32]   ; OldProtect (Arg 5 - Shadow Space Offset)
    mov [rsp + 32], rax   ; Pointer to OldProtect
    
    mov r9, r8            ; NewProtect -> R9 (Arg 4)
    mov r8, rdx           ; RegionSize -> R8 (Arg 3)
    mov rdx, rcx          ; BaseAddress -> RDX (Arg 2)
    mov rcx, -1           ; ProcessHandle (Current) -> RCX (Arg 1)
    
    mov eax, 50h          ; NtProtectVirtualMemory ID
    mov r10, rcx
    syscall
    
    add rsp, 48
    ret
JIT_Lifecycle_Transition ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: JIT_Emit_Template
; Input: RCX = TemplatePtr, RDX = DestOffset, R8 = RegisterMask
; Logic: High-speed patching of JIT stubs using R12 as context base.
; ------------------------------------------------------------------------------
PUBLIC JIT_Emit_Template
JIT_Emit_Template PROC
    ; Assuming R12 is pinned to the JIT region base
    mov rax, [rcx]        ; Load 8-byte template
    or rax, r8            ; Patch in bits (Register indices, etc)
    mov [r12 + rdx], rax  
    ret
JIT_Emit_Template ENDP

END
