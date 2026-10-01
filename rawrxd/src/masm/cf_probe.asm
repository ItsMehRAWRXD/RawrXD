; ============================================================================
; cf_probe.asm -- minimal CreateFileA test, isolated from gguf_probe
; Build:
;   ml64 /nologo /c /Fobuild\cf_probe.obj cf_probe.asm
;   link /nologo /subsystem:console /entry:main /machine:x64 /largeaddressaware:no ^
;        /out:build\cf_probe.exe build\cf_probe.obj kernel32.lib
; ============================================================================
OPTION CASEMAP:NONE

EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN GetLastError:PROC
EXTERN GetStdHandle:PROC
EXTERN GetCommandLineA:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

.data?
ALIGN 16
g_out    QWORD ?
g_numbuf BYTE 32 DUP(?)
g_tmp    BYTE 64 DUP(?)

.data
ALIGN 16
szPath   BYTE "PATH=", 0
szHandle BYTE 13, 10, "HANDLE=", 0
szErr    BYTE 13, 10, "ERRNO=", 0
szCR     BYTE 13, 10, 0

.code

ps PROC
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    xor esi, esi
ps_len:
    cmp BYTE PTR [rbx+rsi], 0
    je ps_go
    inc rsi
    jmp ps_len
ps_go:
    test rsi, rsi
    jz ps_done
    mov rcx, g_out
    mov rdx, rbx
    mov r8, rsi
    xor r9d, r9d
    call WriteFile
ps_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
ps ENDP

pu PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    test rbx, rbx
    jnz pu_go
    mov BYTE PTR [g_tmp], 30h
    mov BYTE PTR [g_tmp+1], 0
    lea rcx, OFFSET g_tmp
    call ps
    jmp pu_done
pu_go:
    mov rax, rbx
    xor esi, esi
pu_div:
    mov rbx, 10
    xor edx, edx
    div rbx
    push rdx
    inc esi
    mov rbx, rax
    test rbx, rbx
    jnz pu_div
pu_emit:
    pop rax
    add al, 30h
    mov BYTE PTR [g_tmp], al
    mov BYTE PTR [g_tmp+1], 0
    lea rcx, OFFSET g_tmp
    call ps
    dec esi
    jnz pu_emit
pu_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
pu ENDP

main PROC
    sub rsp, 68h
    mov rcx, -11
    call GetStdHandle
    mov g_out, rax

    call GetCommandLineA
    mov rbx, rax
    xor esi, esi
scan:
    cmp BYTE PTR [rbx+rsi], 0
    je noarg
    cmp BYTE PTR [rbx+rsi], 20h
    jne next
    inc esi
skip:
    cmp BYTE PTR [rbx+rsi], 20h
    jne got
    inc esi
    jmp skip
got:
    lea rcx, [rbx+rsi]
    jmp have
next:
    inc esi
    jmp scan
noarg:
    mov ecx, 1
    call ExitProcess
have:
    push rcx
    lea rcx, OFFSET szPath
    call ps
    pop rcx
    lea rcx, OFFSET szCR
    call ps

    ; CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
    ;             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
    push rcx
    sub rsp, 68h                   ; 0x68 keeps rsp 16-byte aligned after the push
    mov edx, 80000000h
    mov r8d, 1
    xor r9d, r9d
    mov QWORD PTR [rsp+20h], 3
    mov QWORD PTR [rsp+28h], 80h
    mov QWORD PTR [rsp+30h], 0
    call CreateFileA
    add rsp, 68h
    pop rcx

    lea rcx, OFFSET szHandle
    call ps
    mov rcx, rax
    call pu
    lea rcx, OFFSET szCR
    call ps

    test rax, rax
    jnz opened
    lea rcx, OFFSET szErr
    call ps
    call GetLastError
    mov rcx, rax
    call pu
    lea rcx, OFFSET szCR
    call ps
opened:
    xor ecx, ecx
    call ExitProcess
main ENDP

END