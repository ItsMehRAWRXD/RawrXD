; asm_log_simple.asm - Simple logging function for MASM modules
; Provides asm_log function needed by asm_memory.asm

option casemap:none

.code

; External console logging function
EXTERN console_log:PROC

; Simple asm_log wrapper
PUBLIC asm_log
asm_log PROC
    ; rcx = message pointer
    ; Just forward to console_log
    call console_log
    ret
asm_log ENDP

END




