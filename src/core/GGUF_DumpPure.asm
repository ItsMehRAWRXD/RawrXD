; GGUF_DumpPure.asm - Pure test without gguf_loader's PrintString
option casemap:none

includelib msvcrt.lib
includelib legacy_stdio_definitions.lib

EXTERN printf:PROC
EXTERN exit:PROC
EXTERN CreateFileA:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC

.data
    model_path      db "d:\\test_minimal.gguf", 0
    fmt_header      db "=== GGUF PURE TEST ===", 10, 0
    fmt_open        db "[1] Opening file...", 10, 0
    fmt_size        db "[2] File size: %llu", 10, 0
    fmt_map         db "[3] Creating mapping...", 10, 0
    fmt_view        db "[4] Mapping view...", 10, 0
    fmt_ok          db "[5] SUCCESS! Mapped at %p", 10, 0
    fmt_magic       db "[6] Magic: %08X", 10, 0
    fmt_fail        db "FAILED at step", 10, 0
    
    ; Handles
    file_handle     dq 0
    map_handle      dq 0
    mapped_base     dq 0
    file_size       dq 0
    
    ; Constants
    GENERIC_READ    equ 80000000h
    FILE_SHARE_READ equ 1
    OPEN_EXISTING   equ 3
    FILE_ATTRIBUTE_NORMAL equ 80h
    PAGE_READONLY   equ 2
    FILE_MAP_READ   equ 4
    INVALID_HANDLE_VALUE equ -1

.code

main PROC
    sub     rsp, 72
    
    ; Print header
    lea     rcx, fmt_header
    call    printf
    
    ; Step 1: Open file
    lea     rcx, fmt_open
    call    printf
    
    lea     rcx, model_path
    mov     edx, GENERIC_READ
    mov     r8d, FILE_SHARE_READ
    xor     r9d, r9d
    mov     qword ptr [rsp+32], OPEN_EXISTING
    mov     qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      failed
    mov     [file_handle], rax
    
    ; Step 2: Get file size
    mov     rcx, [file_handle]
    lea     rdx, file_size
    call    GetFileSizeEx
    test    eax, eax
    jz      failed
    
    lea     rcx, fmt_size
    mov     rdx, [file_size]
    call    printf
    
    ; Step 3: Create mapping
    lea     rcx, fmt_map
    call    printf
    
    mov     rcx, [file_handle]
    xor     edx, edx
    mov     r8d, PAGE_READONLY
    xor     r9d, r9d
    mov     rax, [file_size]
    mov     qword ptr [rsp+32], rax
    mov     qword ptr [rsp+40], 0
    call    CreateFileMappingA
    
    test    rax, rax
    jz      failed
    mov     [map_handle], rax
    
    ; Step 4: Map view
    lea     rcx, fmt_view
    call    printf
    
    mov     rcx, [map_handle]
    mov     edx, FILE_MAP_READ
    xor     r8d, r8d
    xor     r9d, r9d
    mov     rax, [file_size]
    mov     qword ptr [rsp+32], rax
    call    MapViewOfFile
    
    test    rax, rax
    jz      failed
    mov     [mapped_base], rax
    
    ; Step 5: Print success
    lea     rcx, fmt_ok
    mov     rdx, [mapped_base]
    call    printf
    
    ; Step 6: Check magic (first 4 bytes)
    mov     rax, [mapped_base]
    mov     edx, [rax]
    lea     rcx, fmt_magic
    call    printf
    
    ; Cleanup
    mov     rcx, [mapped_base]
    call    UnmapViewOfFile
    mov     rcx, [map_handle]
    call    CloseHandle
    mov     rcx, [file_handle]
    call    CloseHandle
    
    xor     ecx, ecx
    call    exit
    
failed:
    lea     rcx, fmt_fail
    call    printf
    mov     ecx, 1
    call    exit
    
    add     rsp, 72
    ret
main ENDP

END
