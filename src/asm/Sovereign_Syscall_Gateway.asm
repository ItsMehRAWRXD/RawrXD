; ==============================================================================
; Sovereign_Syscall_Gateway.asm
; Purpose: Controlled, instrumented syscall dispatch for the Sovereign Engine.
; Zero-Dependency / Pure x64 MASM
; ==============================================================================

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Syscall_Gateway
; Purpose: Execute a syscall with the ID in EAX.
; Follows Windows x64 ABI for syscalls (R10 = RCX).
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Syscall_Gateway
Sovereign_Syscall_Gateway PROC
    ; Align stack and preserve volatile registers that syscall might clobber
    ; (Though Windows syscalls generally preserve most except RAX, RCX, R11)
    push r11
    push rbx
    
    ; The Syscall ID is expected to be in EAX already.
    ; Windows x64 syscall convention expects RCX in R10.
    mov r10, rcx
    syscall
    
    pop rbx
    pop r11
    ret
Sovereign_Syscall_Gateway ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: __chkstk
; Minimal stub to satisfy linker when /NODEFAULTLIB is used.
; ------------------------------------------------------------------------------
PUBLIC __chkstk
__chkstk PROC
    ret                     ; Minimal stub for zero-dependency assembly
__chkstk ENDP

END
