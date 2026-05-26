; ==============================================================================
; Sovereign_Elite_Stealth.asm - Hardened PEB/TEB Anti-Debug
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Stealth_Audit
; Performs multi-stage anti-debug check bypassing standard BeingDebugged.
; Returns RAX = 0 if clean, 1 if debugged.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Stealth_Audit
Sovereign_Stealth_Audit PROC
    ; 1. Standard PEB check (BeingDebugged)
    mov rax, gs:[60h]
    movzx ecx, byte ptr [rax + 2]
    test ecx, ecx
    jnz @@Detected

    ; 2. NtGlobalFlag Check (Offset 0xBC on x64)
    ; Flags like FLG_HEAP_ENABLE_TAIL_CHECK (0x10), 
    ; FLG_HEAP_ENABLE_FREE_CHECK (0x20), 
    ; FLG_HEAP_VALIDATE_PARAMETERS (0x40)
    ; Usually 0x70 when debugged.
    mov ecx, [rax + 0BCh]
    test ecx, 70h
    jnz @@Detected

    ; 3. ProcessHeap Flags Check
    ; Offset 0x30 in PEB is ProcessHeap.
    ; Offset 0x40/0x44 in Heap structure are Flags/ForceFlags.
    mov rax, [rax + 30h]    ; RAX = GetProcessHeap()
    
    ; On Win10+, Flags are at +0x70, ForceFlags at +0x74 usually
    ; If Flags & ~HEAP_GROWABLE (2) != 0, a debugger is likely present.
    mov ecx, [rax + 70h]
    and ecx, 0FFFFFFFDh     ; Filter out HEAP_GROWABLE
    jnz @@Detected

    xor rax, rax            ; Clean
    ret

@@Detected:
    mov rax, 1
    ret
Sovereign_Stealth_Audit ENDP

; ----------------------------------------------------------------------------
; Sovereign_Syscall_ID_Extract
; Parses ntdll.dll exports directly to extract Syscall IDs.
; Bypasses inline hooks by reading the "mov eax, ID" opcode.
; RCX = Target Hash (ROR13)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Syscall_ID_Extract
Sovereign_Syscall_ID_Extract PROC
    ; [Placeholder for ROR13 discovery logic - assumed implemented in PEB_Loader]
    ; Once address is found:
    ; mov eax, [rip_of_ntdll_func + 4] ; Extract the 4-byte ID from 'mov eax, imm32'
    ret
Sovereign_Syscall_ID_Extract ENDP

END
