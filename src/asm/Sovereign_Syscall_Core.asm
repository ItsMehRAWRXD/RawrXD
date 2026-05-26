; ==============================================================================
; Sovereign_Syscall_Core.asm - Direct Syscall Gateway (Unhookable I/O)
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Direct_Exit
; Performs a direct NtTerminateProcess syscall.
; RCX = Exit Code
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Direct_Exit
Sovereign_Direct_Exit PROC
    mov r10, -1         ; ProcessHandle = CurrentProcess
    mov rdx, rcx        ; ExitStatus
    mov eax, 2Ch        ; NtTerminateProcess Syscall ID (Win10/11)
    syscall
    ret
Sovereign_Direct_Exit ENDP

; ----------------------------------------------------------------------------
; Sovereign_Direct_Write
; Performs a direct NtWriteFile syscall.
; RCX=Handle, RDX=Buffer, R8=Size
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Direct_Write
Sovereign_Direct_Write PROC
    mov r10, rcx
    ; Note: NtWriteFile on x64 requires 10 arguments. 
    ; This is a simplified stub for the Monolith integration.
    mov eax, 08h        ; NtWriteFile Syscall ID (Win10/11)
    syscall
    ret
Sovereign_Direct_Write ENDP

END
