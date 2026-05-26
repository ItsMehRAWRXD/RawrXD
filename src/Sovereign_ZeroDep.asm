; =============================================================================
; SOVEREIGN_ZERODEP.ASM - v24.0.0-PROD
; Zero-Dependency x64 MASM
; =============================================================================

OPTION CASEMAP:NONE

STD_OUTPUT_HANDLE    equ -11
HASH_ExitProcess            equ 02E2D4486h
HASH_GetStdHandle           equ 032EC80F7h
HASH_WriteFile              equ 0D5C754A9h

.DATA
    msg_boot    db "SOVEREIGN BOOT OK", 13, 10, 0
    hStdOut     dq 0
    _WriteFile  dq 0
    _ExitProcess dq 0
    _GetStdHandle dq 0
    bytesWritten dq 0

.CODE

; Using the most reliable way: scan for kernel32.dll export signatures if needed,
; but let's try the absolute head pointer.
GetKernel32Base PROC
    mov rax, gs:[60h]
    mov rax, [rax + 18h]    ; Ldr
    mov rax, [rax + 10h]    ; InLoadOrder (pointing to head)
    ; InLoadOrder link at 0x00, DllBase at 0x30
    mov rax, [rax]          ; skip EXE
    mov rax, [rax]          ; ntdll.dll
    mov rax, [rax]          ; kernel32.dll
    mov rax, [rax + 30h]    ; DllBase
    ret
GetKernel32Base ENDP

GetProcAddressByHash PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov r9, rcx
    mov r10d, edx
    mov eax, [r9 + 3Ch]
    add rax, r9
    mov eax, [rax + 88h]
    add rax, r9
    mov r11, rax
    mov ecx, [r11 + 18h]
    mov r8d, [r11 + 20h]
    add r8, r9
@loop:
    dec ecx
    js @fail
    mov eax, [r8 + rcx*4]
    add rax, r9
    xor edx, edx
@h: movzx ebx, byte ptr [rax]
    test bl, bl
    jz @chk
    ror edx, 13
    add edx, ebx
    inc rax
    jmp @h
@chk:
    cmp edx, r10d
    jne @loop
    mov r8d, [r11 + 24h]
    add r8, r9
    movzx eax, word ptr [r8 + rcx*2]
    mov r8d, [r11 + 1Ch]
    add r8, r9
    mov eax, [r8 + rax*4]
    add rax, r9
    leave
    ret
@fail:
    xor rax, rax
    leave
    ret
GetProcAddressByHash ENDP

main PROC
    sub rsp, 88
    call GetKernel32Base
    mov rsi, rax
    
    mov rcx, rsi
    mov edx, HASH_GetStdHandle
    call GetProcAddressByHash
    mov [_GetStdHandle], rax
    
    mov rcx, rsi
    mov edx, HASH_WriteFile
    call GetProcAddressByHash
    mov [_WriteFile], rax
    
    mov rcx, rsi
    mov edx, HASH_ExitProcess
    call GetProcAddressByHash
    mov [_ExitProcess], rax
    
    mov rcx, STD_OUTPUT_HANDLE
    call [_GetStdHandle]
    mov [hStdOut], rax
    
    mov rcx, rax
    lea rdx, msg_boot
    mov r8, 17
    lea r9, bytesWritten
    mov qword ptr [rsp + 32], 0
    call [_WriteFile]
    
    xor rcx, rcx
    call [_ExitProcess]
main ENDP
end
