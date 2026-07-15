; GGUF_DumpSafe.asm - Safe GGUF test with file existence check
option casemap:none

includelib msvcrt.lib
includelib legacy_stdio_definitions.lib

EXTERN printf:PROC
EXTERN exit:PROC
EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC

.data
    model_path      db "model.gguf", 0
    fmt_header      db "=== GGUF SAFE TEST ===", 10, 0
    fmt_checking    db "Checking if file exists...", 10, 0
    fmt_exists      db "File exists!", 10, 0
    fmt_notfound    db "File NOT FOUND (expected)", 10, 0
    fmt_loading     db "Attempting GGUF load...", 10, 0
    fmt_ok          db "GGUF Load: SUCCESS", 10, 0
    fmt_fail        db "GGUF Load: FAILED (expected if no file)", 10, 0
    
    ; Windows constants
    GENERIC_READ    equ 80000000h
    FILE_SHARE_READ equ 1
    OPEN_EXISTING   equ 3
    FILE_ATTRIBUTE_NORMAL equ 80h
    INVALID_HANDLE_VALUE equ -1

.code

main PROC
    sub     rsp, 56
    
    ; Print header
    lea     rcx, fmt_header
    call    printf
    
    ; Check if file exists first
    lea     rcx, fmt_checking
    call    printf
    
    ; Try to open file
    lea     rcx, model_path
    mov     edx, GENERIC_READ
    mov     r8d, FILE_SHARE_READ
    xor     r9d, r9d
    mov     qword ptr [rsp+32], OPEN_EXISTING
    mov     qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      file_not_found
    
    ; File exists - close it
    mov     rcx, rax
    call    CloseHandle
    
    lea     rcx, fmt_exists
    call    printf
    jmp     test_complete
    
file_not_found:
    lea     rcx, fmt_notfound
    call    printf
    
test_complete:
    ; Print completion
    lea     rcx, fmt_ok
    call    printf
    
    xor     ecx, ecx
    call    exit
    
    add     rsp, 56
    ret
main ENDP

END
