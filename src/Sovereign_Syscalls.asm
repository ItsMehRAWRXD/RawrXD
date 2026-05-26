; Sovereign_Syscalls.asm - Direct NT Executive Interaction (Ring 3)
; Bypasses Kernel32/KernelBase redirection and monitoring.

include Sovereign_Common.inc

.code

; ------------------------------------------------------------------------------
; Sovereign_Sys_Allocate
; RCX = ProcessHandle (-1)
; RDX = BaseAddress (Pointer to Pointer)
; R8  = ZeroBits
; R9  = RegionSize (Pointer to Size)
; [RSP+28h] = AllocationType
; [RSP+30h] = Protect
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Sys_Allocate
Sovereign_Sys_Allocate PROC
    mov r10, rcx
    mov eax, 18h            ; NtAllocateVirtualMemory (Win10/11)
    syscall
    ret
Sovereign_Sys_Allocate ENDP

; ------------------------------------------------------------------------------
; Sovereign_Sys_Protect
; RCX = ProcessHandle
; RDX = BaseAddress
; R8  = RegionSize
; R9  = NewProtect
; [RSP+28h] = OldProtect
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Sys_Protect
Sovereign_Sys_Protect PROC
    mov r10, rcx
    mov eax, 50h            ; NtProtectVirtualMemory (Win10/11)
    syscall
    ret
Sovereign_Sys_Protect ENDP

; ------------------------------------------------------------------------------
; Sovereign_Sys_WriteMemory
; RCX = ProcessHandle
; RDX = BaseAddress
; R8  = Buffer
; R9  = Size
; [RSP+28h] = BytesWritten
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Sys_WriteMemory
Sovereign_Sys_WriteMemory PROC
    mov r10, rcx
    mov eax, 3Ah            ; NtWriteVirtualMemory (Win10/11)
    syscall
    ret
Sovereign_Sys_WriteMemory ENDP

; ------------------------------------------------------------------------------
; SYSCALL: Elite_NtAllocateVirtualMemory (x64)
; Allows dynamic allocation without LoadLibrary/GetProcAddress reliance.
; ID: 18h (Win10/11)
; ------------------------------------------------------------------------------
PUBLIC Elite_NtAllocateVirtualMemory
Elite_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h            
    syscall
    ret
Elite_NtAllocateVirtualMemory ENDP

; ------------------------------------------------------------------------------
; SYSCALL: Elite_NtProtectVirtualMemory (x64)
; ID: 50h
; ------------------------------------------------------------------------------
PUBLIC Elite_NtProtectVirtualMemory
Elite_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 50h
    syscall
    ret
Elite_NtProtectVirtualMemory ENDP

END
