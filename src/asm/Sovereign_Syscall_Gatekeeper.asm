; ==============================================================================
; Sovereign_Syscall_Gatekeeper.asm
; Logic: Direct Syscall Dispatcher (Bypassing ntdll.dll)
; Standard: x64 Windows ABI Compliance
; ==============================================================================

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: XR_Invoke_Syscall
; Input: EAX = SyscallID
;        RCX = Arg 1
;        RDX = Arg 2
;        R8  = Arg 3
;        R9  = Arg 4
; Note: Arguments 5+ are expected to be on the stack per x64 ABI.
;       The syscall instruction clobbers RCX and R11.
; ------------------------------------------------------------------------------
PUBLIC XR_Invoke_Syscall
XR_Invoke_Syscall PROC
    ; 1. Preserve registers that syscall clobbers but are non-volatile in ABI (if any)
    ; Actually, RCX and R11 are volatile in the Windows x64 ABI.
    ; However, the kernel expects the first argument in R10, not RCX.
    
    mov r10, rcx    ; Pivot Arg 1 to R10 for kernel transition
    syscall         ; Transition to Ring 0
    ret
XR_Invoke_Syscall ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: XR_Resolve_Syscall_ID
; Logic: Dynamic lookup for syscall IDs by parsing ntdll in memory.
; Input: RCX = Pointer to function name string (e.g., "NtWriteFile")
; Output: EAX = Syscall ID, or -1 if not found.
; ------------------------------------------------------------------------------
PUBLIC XR_Resolve_Syscall_ID
XR_Resolve_Syscall_ID PROC
    ; [REDACTED: Full PE Export Table Parsing Logic]
    ; This would traverse the EAT of ntdll.dll (found via PEB)
    ; to find the 'mov eax, <id>' opcode (0xB8) at the function entry.
    xor eax, eax
    dec eax ; Return -1 for now until PEB loader provides ntdll base
    ret
XR_Resolve_Syscall_ID ENDP

END
