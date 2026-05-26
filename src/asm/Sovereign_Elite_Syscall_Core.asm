; Sovereign_Elite_Syscall_Core.asm
include Sovereign_Common.inc
.DATA
ALIGN 16
g_Syscall_Override_Table dq 256 DUP(0)
.CODE
PUBLIC Elite_Syscall_Gateway
Elite_Syscall_Gateway PROC
push r11
push r10
mov r10, rcx
lea r11, [g_Syscall_Override_Table]
mov r11, [r11 + rax*8]
test r11, r11
jnz @@Override
syscall
pop r10
pop r11
ret
@@Override:
pop r10
pop r11
jmp r11
Elite_Syscall_Gateway ENDP
PUBLIC Elite_NtProtectVirtualMemory
Elite_NtProtectVirtualMemory PROC
mov eax, 50h
jmp Elite_Syscall_Gateway
Elite_NtProtectVirtualMemory ENDP
PUBLIC JIT_Patch_Syscall
JIT_Patch_Syscall PROC
lea r8, [g_Syscall_Override_Table]
mov [r8 + rcx*8], rdx
ret
JIT_Patch_Syscall ENDP
END
