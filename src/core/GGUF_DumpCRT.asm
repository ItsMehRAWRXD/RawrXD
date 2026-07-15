; GGUF_DumpCRT.asm - Test with CRT printf
option casemap:none

includelib msvcrt.lib
includelib legacy_stdio_definitions.lib

EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC

EXTERN printf:PROC
EXTERN exit:PROC

.data
    model_path      db "model.gguf", 0
    fmt_header      db "=== GGUF CRT TEST ===", 10, 0
    fmt_loading     db "Loading GGUF...", 10, 0
    fmt_ok          db "SUCCESS: Handle=%p", 10, 0
    fmt_fail        db "FAILED", 10, 0
    gguf_handle     dq 0

.code

main PROC
    sub     rsp, 40
    
    ; Print header
    lea     rcx, fmt_header
    call    printf
    
    ; Print loading message
    lea     rcx, fmt_loading
    call    printf
    
    ; Try to load GGUF
    lea     rcx, model_path
    lea     rdx, gguf_handle
    call    GGUF_LoadFile
    
    test    rax, rax
    jz      failed
    
    ; Success
    lea     rcx, fmt_ok
    mov     rdx, [gguf_handle]
    call    printf
    
    ; Cleanup
    mov     rcx, [gguf_handle]
    call    GGUF_UnloadFile
    
    xor     ecx, ecx
    call    exit
    
failed:
    lea     rcx, fmt_fail
    call    printf
    mov     ecx, 1
    call    exit
    
    add     rsp, 40
    ret
main ENDP

END
