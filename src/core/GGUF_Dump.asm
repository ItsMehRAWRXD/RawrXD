; GGUF_Dump.asm - Verify GGUF loader with real file
; Dumps header info from model.gguf

option casemap:none

EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC
EXTERNDEF GGUF_ParseHeader:PROC
EXTERNDEF PrintString:PROC
EXTERNDEF PrintNumber:PROC
EXTERNDEF ExitProcess:PROC

.data
    ; File path
    model_path      db "model.gguf", 0
    
    ; Messages
    msg_header      db "=== GGUF HEADER DUMP ===", 13, 10, 0
    msg_loading     db "[1] Loading GGUF file...", 13, 10, 0
    msg_loaded      db "[2] File mapped successfully", 13, 10, 0
    msg_magic       db "[3] Magic: ", 0
    msg_version     db "[4] Version: ", 0
    msg_tensors     db "[5] Tensor Count: ", 0
    msg_kv          db "[6] KV Pairs: ", 0
    msg_data_offset db "[7] Data Offset: ", 0
    msg_ok          db "=== GGUF VALID ===", 13, 10, 0
    msg_fail        db "=== GGUF FAILED ===", 13, 10, 0
    newline         db 13, 10, 0
    
    ; Handle
    gguf_handle     dq 0
    
    ; Header info (GGUF v3 layout)
    ; Offset 0: Magic (4 bytes) - "GGUF"
    ; Offset 4: Version (4 bytes)
    ; Offset 8: Tensor Count (8 bytes)
    ; Offset 16: KV Count (8 bytes)

.code

main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Print header
    lea     rcx, msg_header
    call    PrintString
    
    ; Step 1: Try to load file
    lea     rcx, msg_loading
    call    PrintString
    
    lea     rcx, model_path
    lea     rdx, gguf_handle
    call    GGUF_LoadFile
    
    test    rax, rax
    jz      load_failed
    
    ; Step 2: Success!
    lea     rcx, msg_loaded
    call    PrintString
    
    ; Step 3: Dump header info
    ; For now, just show the handle value
    lea     rcx, msg_magic
    call    PrintString
    mov     rcx, [gguf_handle]
    call    PrintNumber64
    lea     rcx, newline
    call    PrintString
    
    ; Show success
    lea     rcx, msg_ok
    call    PrintString
    
    ; Cleanup
    mov     rcx, [gguf_handle]
    call    GGUF_UnloadFile
    
    xor     eax, eax
    jmp     done
    
load_failed:
    lea     rcx, msg_fail
    call    PrintString
    mov     eax, 1
    
done:
    add     rsp, 64
    pop     rbp
    ret
main ENDP

PrintNumber64 PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    sub     rsp, 72
    
    mov     rax, rcx
    lea     rdi, [rsp+32]
    mov     byte ptr [rdi+20], 0
    mov     ebx, 10
    mov     ecx, 20
    
    test    rax, rax
    jnz     convert_loop
    mov     byte ptr [rdi+19], '0'
    mov     byte ptr [rdi+20], 0
    lea     rcx, [rdi+19]
    call    PrintString
    jmp     done_64
    
convert_loop:
    xor     edx, edx
    div     rbx
    add     dl, '0'
    dec     ecx
    mov     [rdi+rcx], dl
    test    rax, rax
    jnz     convert_loop
    
    lea     rcx, [rdi+rcx]
    call    PrintString
    
done_64:
    add     rsp, 72
    pop     rdi
    pop     rbx
    pop     rbp
    ret
PrintNumber64 ENDP

END
