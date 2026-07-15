; StepByStep.asm - Test each component separately
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

EXTERNDEF printf:PROC
EXTERNDEF exit:PROC
EXTERNDEF CreateFileA:PROC
EXTERNDEF GetFileSizeEx:PROC
EXTERNDEF CreateFileMappingA:PROC
EXTERNDEF MapViewOfFile:PROC
EXTERNDEF UnmapViewOfFile:PROC
EXTERNDEF CloseHandle:PROC

.data
    filename    db "test_minimal.gguf", 0
    fmt_start   db "=== STEP BY STEP ===", 10, 0
    fmt_step1   db "[1] Opening file...", 10, 0
    fmt_step2   db "[2] Getting size...", 10, 0
    fmt_step3   db "[3] Creating mapping...", 10, 0
    fmt_step4   db "[4] Mapping view...", 10, 0
    fmt_step5   db "[5] Checking magic...", 10, 0
    fmt_ok      db "    OK", 10, 0
    fmt_fail    db "    FAIL", 10, 0
    fmt_done    db "=== SUCCESS ===", 10, 0
    
    file_handle dq 0
    file_size   dq 0
    map_handle  dq 0
    map_view    dq 0

.code
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    lea     rcx, fmt_start
    call    printf
    
    ; Step 1: Open file
    lea     rcx, fmt_step1
    call    printf
    
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
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Step 2: Get size
    lea     rcx, fmt_step2
    call    printf
    
    mov     rcx, file_handle
    lea     rdx, file_size
    call    GetFileSizeEx
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Step 3: Create mapping
    lea     rcx, fmt_step3
    call    printf
    
    mov     rcx, file_handle
    xor     edx, edx
    mov     r8d, 2
    xor     r9d, r9d
    mov     rax, file_size
    mov     qword ptr [rsp+32], rax
    call    CreateFileMappingA
    
    test    rax, rax
    jz      cleanup
    mov     map_handle, rax
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Step 4: Map view
    lea     rcx, fmt_step4
    call    printf
    
    mov     rcx, map_handle
    mov     edx, 4
    xor     r8d, r8d
    xor     r9d, r9d
    mov     rax, file_size
    mov     qword ptr [rsp+32], rax
    call    MapViewOfFile
    
    test    rax, rax
    jz      cleanup
    mov     map_view, rax
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Step 5: Check magic
    lea     rcx, fmt_step5
    call    printf
    
    mov     rax, map_view
    mov     eax, dword ptr [rax]
    cmp     eax, 46554747h
    jne     cleanup
    
    lea     rcx, fmt_ok
    call    printf
    
    lea     rcx, fmt_done
    call    printf
    
cleanup:
    mov     rcx, map_view
    test    rcx, rcx
    jz      @F
    call    UnmapViewOfFile
@@:
    mov     rcx, map_handle
    test    rcx, rcx
    jz      @F
    call    CloseHandle
@@:
    mov     rcx, file_handle
    test    rcx, rcx
    jz      @F
    call    CloseHandle
@@:
    
    xor     ecx, ecx
    call    exit
    
fail:
    lea     rcx, fmt_fail
    call    printf
    mov     ecx, 1
    call    exit
    
    add     rsp, 64
    pop     rbp
    ret
main ENDP
END
