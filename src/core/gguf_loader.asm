; ============================================================================
; gguf_loader.asm - Real GGUF File Loading with Memory Mapping
; ============================================================================
; Uses Windows CreateFileMappingA / MapViewOfFile for zero-copy loading
; ============================================================================

    .code
    option casemap:none

; External imports
extern CreateFileA:proc
extern CreateFileMappingA:proc
extern MapViewOfFile:proc
extern UnmapViewOfFile:proc
extern CloseHandle:proc
extern GetFileSizeEx:proc
extern GetLastError:proc
extern ExitProcess:proc

; =============================================================================
; CONSTANTS
; =============================================================================
GGUF_MAGIC              equ 46554747h   ; "GGUF" in little-endian
GGUF_VERSION            equ 3

; Windows constants
GENERIC_READ            equ 80000000h
FILE_SHARE_READ         equ 1
OPEN_EXISTING           equ 3
FILE_ATTRIBUTE_NORMAL   equ 80h
PAGE_READONLY           equ 2
FILE_MAP_READ           equ 4

INVALID_HANDLE_VALUE    equ -1

; =============================================================================
; DATA SECTION
; =============================================================================
    .data

gguf_file_path          db "model.gguf", 0
gguf_file_handle        dq 0
gguf_mapping_handle     dq 0
gguf_mapped_base        dq 0
gguf_file_size          dq 0

; GGUF Header structure (simplified)
align 8
gguf_header:
    magic           dd 0
    version         dd 0
    tensor_count    dq 0
    metadata_count  dq 0

; Error messages
msg_opening             db "[GGUF] Opening file...", 13, 10, 0
msg_mapping             db "[GGUF] Creating file mapping...", 13, 10, 0
msg_view                db "[GGUF] Mapping view...", 13, 10, 0
msg_success             db "[GGUF] Successfully mapped! Size: ", 0
msg_bytes               db " bytes", 13, 10, 0
msg_error               db "[GGUF] Error: ", 0
msg_crlf                db 13, 10, 0

; Number buffer for printing
number_buffer           db 32 dup(0)

; =============================================================================
; CODE SECTION
; =============================================================================
    .code

; -----------------------------------------------------------------------------
; GGUF_LoadFile - Load a GGUF file using memory mapping
; Input:  RCX = pointer to file path string
; Output: RAX = base address of mapped file (0 on failure)
; -----------------------------------------------------------------------------
GGUF_LoadFile PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 48
    .allocstack 48
    .endprolog

    mov     rbx, rcx                    ; Save file path

    ; Print status
    lea     rcx, msg_opening
    call    PrintString

    ; CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
    mov     rcx, rbx                    ; lpFileName
    mov     edx, GENERIC_READ           ; dwDesiredAccess
    mov     r8d, FILE_SHARE_READ        ; dwShareMode
    xor     r9d, r9d                    ; lpSecurityAttributes = NULL
    mov     qword ptr [rsp + 32], OPEN_EXISTING      ; dwCreationDisposition
    mov     qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL  ; dwFlagsAndAttributes
    mov     qword ptr [rsp + 48], 0     ; hTemplateFile = NULL
    call    CreateFileA
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      @load_fail_file
    
    mov     [gguf_file_handle], rax

    ; GetFileSizeEx
    lea     rcx, msg_mapping
    call    PrintString
    
    mov     rcx, [gguf_file_handle]
    lea     rdx, gguf_file_size
    call    GetFileSizeEx
    test    eax, eax
    jz      @load_fail_size

    ; CreateFileMappingA
    mov     rcx, [gguf_file_handle]     ; hFile
    xor     edx, edx                    ; lpFileMappingAttributes = NULL
    mov     r8d, PAGE_READONLY          ; flProtect
    mov     r9d, dword ptr [gguf_file_size + 4]  ; dwMaximumSizeHigh
    mov     eax, dword ptr [gguf_file_size]      ; dwMaximumSizeLow
    mov     qword ptr [rsp + 32], rax   ; dwMaximumSizeLow
    xor     eax, eax
    mov     qword ptr [rsp + 40], rax   ; lpName = NULL
    call    CreateFileMappingA
    
    test    rax, rax
    jz      @load_fail_mapping
    
    mov     [gguf_mapping_handle], rax

    ; MapViewOfFile
    lea     rcx, msg_view
    call    PrintString
    
    mov     rcx, [gguf_mapping_handle]  ; hFileMappingObject
    mov     edx, FILE_MAP_READ          ; dwDesiredAccess
    xor     r8d, r8d                    ; dwFileOffsetHigh
    xor     r9d, r9d                    ; dwFileOffsetLow
    mov     rax, [gguf_file_size]
    mov     qword ptr [rsp + 32], rax   ; dwNumberOfBytesToMap
    call    MapViewOfFile
    
    test    rax, rax
    jz      @load_fail_view
    
    mov     [gguf_mapped_base], rax

    ; Success - print size
    lea     rcx, msg_success
    call    PrintString
    
    mov     rcx, [gguf_file_size]
    call    PrintNumber
    
    lea     rcx, msg_bytes
    call    PrintString

    mov     rax, [gguf_mapped_base]
    jmp     @load_done

@load_fail_file:
    lea     rcx, msg_error
    call    PrintString
    mov     rcx, 1
    call    PrintNumber
    jmp     @load_fail

@load_fail_size:
    lea     rcx, msg_error
    call    PrintString
    mov     rcx, 2
    call    PrintNumber
    jmp     @load_cleanup_file

@load_fail_mapping:
    lea     rcx, msg_error
    call    PrintString
    mov     rcx, 3
    call    PrintNumber
    jmp     @load_cleanup_file

@load_fail_view:
    lea     rcx, msg_error
    call    PrintString
    mov     rcx, 4
    call    PrintNumber
    jmp     @load_cleanup_mapping

@load_cleanup_mapping:
    mov     rcx, [gguf_mapping_handle]
    call    CloseHandle

@load_cleanup_file:
    mov     rcx, [gguf_file_handle]
    call    CloseHandle

@load_fail:
    xor     rax, rax

@load_done:
    add     rsp, 48
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    ret
GGUF_LoadFile ENDP

; -----------------------------------------------------------------------------
; GGUF_UnloadFile - Unmap and close the GGUF file
; -----------------------------------------------------------------------------
GGUF_UnloadFile PROC FRAME
    push    rbp
    mov     rbp, rsp
    .endprolog

    mov     rcx, [gguf_mapped_base]
    test    rcx, rcx
    jz      @skip_unmap
    call    UnmapViewOfFile

@skip_unmap:
    mov     rcx, [gguf_mapping_handle]
    test    rcx, rcx
    jz      @skip_close_mapping
    call    CloseHandle

@skip_close_mapping:
    mov     rcx, [gguf_file_handle]
    test    rcx, rcx
    jz      @skip_close_file
    call    CloseHandle

@skip_close_file:
    pop     rbp
    ret
GGUF_UnloadFile ENDP

; -----------------------------------------------------------------------------
; GGUF_ParseHeader - Parse the GGUF header from mapped memory
; Input:  RCX = mapped base address
; Output: RAX = pointer to first tensor info (0 on failure)
; -----------------------------------------------------------------------------
GGUF_ParseHeader PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    .endprolog

    mov     rbx, rcx                    ; RBX = base

    ; Check magic
    mov     eax, [rbx]
    cmp     eax, GGUF_MAGIC
    jne     @parse_fail

    ; Check version
    mov     eax, [rbx + 4]
    cmp     eax, GGUF_VERSION
    jne     @parse_fail

    ; Check magic and version
    mov     eax, [rbx]
    cmp     eax, GGUF_MAGIC
    jne     @parse_fail

    mov     eax, [rbx + 4]
    cmp     eax, GGUF_VERSION
    jne     @parse_fail

    ; Return pointer to metadata (after header)
    lea     rax, [rbx + 24]
    jmp     @parse_done

@parse_fail:
    xor     rax, rax

@parse_done:
    pop     rbx
    pop     rbp
    ret
GGUF_ParseHeader ENDP

; -----------------------------------------------------------------------------
; PrintString - Print a null-terminated string
; Input: RCX = string pointer
; -----------------------------------------------------------------------------
PrintString PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 40

    mov     rbx, rcx                    ; RBX = string

    ; Get string length
    xor     eax, eax
    mov     rdi, rbx
    mov     ecx, 0FFFFFFFFh
    repne scasb
    not     ecx
    dec     ecx                         ; ECX = length

    ; Write to stdout (handle = -11)
    mov     rdx, rbx                    ; lpBuffer
    mov     r8d, ecx                    ; nNumberOfBytesToWrite
    lea     r9, [rsp + 32]              ; lpNumberOfBytesWritten
    mov     rcx, -11                    ; hConsoleOutput (stdout)
    call    WriteConsoleA

    add     rsp, 40
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    ret
PrintString ENDP

; -----------------------------------------------------------------------------
; PrintNumber - Print a 64-bit unsigned integer
; Input: RCX = number
; -----------------------------------------------------------------------------
PrintNumber PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rax, rcx                    ; RAX = number
    lea     rbx, number_buffer + 31     ; RBX = end of buffer
    mov     byte ptr [rbx], 0           ; null terminate

    ; Special case for 0
    test    rax, rax
    jnz     @convert_loop
    mov     byte ptr [rbx - 1], '0'
    dec     rbx
    jmp     @print_num

@convert_loop:
    xor     edx, edx
    mov     r8d, 10
    div     r8d                         ; RAX = RAX / 10, RDX = remainder
    add     dl, '0'
    dec     rbx
    mov     [rbx], dl
    test    rax, rax
    jnz     @convert_loop

@print_num:
    mov     rcx, rbx
    call    PrintString

    add     rsp, 40
    pop     rbx
    pop     rbp
    ret
PrintNumber ENDP

; External import for console output
extern WriteConsoleA:proc

; =============================================================================
; EXPORTS
; =============================================================================
PUBLIC GGUF_LoadFile
PUBLIC GGUF_UnloadFile
PUBLIC GGUF_ParseHeader
PUBLIC PrintString
PUBLIC PrintNumber

    END
