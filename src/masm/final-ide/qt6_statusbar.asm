; ==========================================================================
; MASM Qt6 Component Conversion: StatusBar Layer (CLEAN)
; ==========================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc
includelib kernel32.lib
includelib user32.lib

; External foundation functions
EXTERN object_create:PROC

.code

PUBLIC status_bar_create
status_bar_create PROC
    push rbx
    sub rsp, 32
    
    mov rcx, 4                  ; Type ID for StatusBar
    mov rdx, rcx                ; Parent
    call object_create
    
    add rsp, 32
    pop rbx
    ret
status_bar_create ENDP

PUBLIC status_bar_set_message
status_bar_set_message PROC
    xor rax, rax
    ret
status_bar_set_message ENDP

END
