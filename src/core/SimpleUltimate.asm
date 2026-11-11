; SimpleUltimate.asm - Minimal working version
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

EXTERNDEF printf:PROC
EXTERNDEF exit:PROC
EXTERNDEF CreateFileA:PROC
EXTERNDEF GetFileSizeEx:PROC
EXTERNDEF CloseHandle:PROC

.data
    filename    db "test_minimal.gguf", 0
    fmt_start   db "=== ULTIMATE TEST ===", 10, 0
    fmt_file    db "File: %s", 10, 0
    fmt_size    db "Size: %llu bytes", 10, 0
    fmt_ok      db "SUCCESS!", 10, 0
    
    file_handle dq 0
    file_size   dq 0

.code
main PROC
    sub     rsp, 40
    
    lea     rcx, fmt_start
    call    printf
    
    ; Open file
    mov     rcx, offset filename
    mov     edx, 80000000h
    mov     r8d, 3
    xor     r9d, r9d
    mov     dword ptr [rsp+32], 3
    mov     dword ptr [rsp+40], 80h
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    
    cmp     rax, 0FFFFFFFFFFFFFFFFh
    je      fail
    mov     file_handle, rax
    
    lea     rcx, fmt_file
    mov     rdx, offset filename
    call    printf
    
    ; Get size
    mov     rcx, file_handle
    lea     rdx, file_size
    call    GetFileSizeEx
    
    lea     rcx, fmt_size
    mov     rdx, file_size
    call    printf
    
    ; Close file
    mov     rcx, file_handle
    call    CloseHandle
    
    lea     rcx, fmt_ok
    call    printf
    
    xor     ecx, ecx
    call    exit
    
fail:
    mov     ecx, 1
    call    exit
    
    add     rsp, 40
    ret
main ENDP
END
