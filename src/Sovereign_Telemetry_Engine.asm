; Sovereign_Log.asm
; Lock-free write to the Titan Telemetry Page
.data
    ALIGN 16
    LOG_BUFFER_SIZE equ 4096
    g_LogHead       dq 0
    g_LogBuffer     db LOG_BUFFER_SIZE dup(0)

.code
PUBLIC Sovereign_LogEvent
Sovereign_LogEvent proc
    ; RCX = Pointer to 8-byte event tag
    ; RDX = Value
    
    ; Atomic increment of index
    mov rax, 16         ; Log entry size (8 tag + 8 value)
    lock xadd g_LogHead, rax
    
    ; Wrap index
    and rax, (LOG_BUFFER_SIZE - 1)
    
    ; Write to buffer
    lea r8, g_LogBuffer
    mov r9, [rcx]
    mov [r8 + rax], r9
    mov [r8 + rax + 8], rdx
    ret
Sovereign_LogEvent endp
end