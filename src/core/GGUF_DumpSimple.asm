; GGUF_DumpSimple.asm - Simple GGUF test without FRAME directives
option casemap:none

EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC
EXTERNDEF PrintString:PROC
EXTERNDEF PrintNumber:PROC
EXTERNDEF ExitProcess:PROC

.data
    model_path      db "model.gguf", 0
    msg_header      db "=== GGUF TEST ===", 13, 10, 0
    msg_loading     db "Loading...", 13, 10, 0
    msg_ok          db "SUCCESS", 13, 10, 0
    msg_fail        db "FAILED", 13, 10, 0
    newline         db 13, 10, 0
    gguf_handle     dq 0

.code

main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    lea     rcx, msg_header
    call    PrintString
    
    lea     rcx, msg_loading
    call    PrintString
    
    ; Try to load
    lea     rcx, model_path
    lea     rdx, gguf_handle
    call    GGUF_LoadFile
    
    test    rax, rax
    jz      failed
    
    lea     rcx, msg_ok
    call    PrintString
    
    ; Cleanup
    mov     rcx, [gguf_handle]
    call    GGUF_UnloadFile
    
    xor     eax, eax
    jmp     done
    
failed:
    lea     rcx, msg_fail
    call    PrintString
    mov     eax, 1
    
done:
    add     rsp, 64
    pop     rbp
    ret
main ENDP

END
