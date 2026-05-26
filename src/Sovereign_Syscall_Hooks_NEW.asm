; ============================================================================
; Sovereign_Syscall_Hooks.asm — Direct NT Kernel Interface
; Hardcoded syscall numbers for Windows 10 1903+ / Windows 11 x64
; ============================================================================
OPTION CASEMAP:NONE

.CODE

NtWriteFile_num      equ 0008h
NtReadFile_num       equ 0006h
NtClose_num          equ 000Fh
NtAllocateVirtualMemory_num equ 0018h
NtFreeVirtualMemory_num     equ 001Eh

PUBLIC Syscall_NtWriteFile
Syscall_NtWriteFile PROC
    mov r10, rcx
    mov eax, NtWriteFile_num
    syscall
    ret
Syscall_NtWriteFile ENDP

PUBLIC Syscall_NtReadFile
Syscall_NtReadFile PROC
    mov r10, rcx
    mov eax, NtReadFile_num
    syscall
    ret
Syscall_NtReadFile ENDP

PUBLIC Syscall_NtClose
Syscall_NtClose PROC
    mov r10, rcx
    mov eax, NtClose_num
    syscall
    ret
Syscall_NtClose ENDP

PUBLIC Syscall_NtAllocateVirtualMemory
Syscall_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, NtAllocateVirtualMemory_num
    syscall
    ret
Syscall_NtAllocateVirtualMemory ENDP

PUBLIC Syscall_NtFreeVirtualMemory
Syscall_NtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, NtFreeVirtualMemory_num
    syscall
    ret
Syscall_NtFreeVirtualMemory ENDP

END