; GGUF_DumpReal.asm - Test with real GGUF file
option casemap:none

includelib msvcrt.lib
includelib legacy_stdio_definitions.lib

EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC

EXTERN printf:PROC
EXTERN exit:PROC

.data
    ; Use the test_minimal.gguf file
    model_path      db "d:\\test_minimal.gguf", 0
    fmt_header      db "=== GGUF REAL FILE TEST ===", 10, 0
    fmt_loading     db "Loading: %s", 10, 0
    fmt_ok          db "SUCCESS! Mapped at %p", 10, 0
    fmt_fail        db "FAILED to load", 10, 0
    fmt_cleanup     db "Cleanup complete", 10, 0
    gguf_handle     dq 0

.code

main PROC
    sub     rsp, 56
    
    ; Print header
    lea     rcx, fmt_header
    call    printf
    
    ; Print file path
    lea     rcx, fmt_loading
    lea     rdx, model_path
    call    printf
    
    ; Try to load GGUF
    lea     rcx, model_path
    lea     rdx, gguf_handle
    call    GGUF_LoadFile
    
    test    rax, rax
    jz      failed
    
    ; Success
    lea     rcx, fmt_ok
    mov     rdx, rax
    call    printf
    
    ; Cleanup
    mov     rcx, [gguf_handle]
    call    GGUF_UnloadFile
    
    lea     rcx, fmt_cleanup
    call    printf
    
    xor     ecx, ecx
    call    exit
    
failed:
    lea     rcx, fmt_fail
    call    printf
    mov     ecx, 1
    call    exit
    
    add     rsp, 56
    ret
main ENDP

END
