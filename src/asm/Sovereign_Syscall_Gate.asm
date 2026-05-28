; ==================================================================================
; SYSCALL GATE - SINGLE OS BOUNDARY CONTRACT
; ==================================================================================

.CODE

PUBLIC Sovereign_Syscall_Dispatch

Sovereign_Syscall_Dispatch PROC
    ENTER_FRAME

    ; validate syscall index
    cmp ecx, 0
    jl bad_sys
    cmp ecx, 0FFFFh
    jg bad_sys

    mov r10, rcx
    mov eax, r10d

    syscall

    EXIT_FRAME

bad_sys:
    FAIL_FAST 0C0000005h
Sovereign_Syscall_Dispatch ENDP
