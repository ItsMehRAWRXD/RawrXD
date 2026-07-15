; ============================================================================
; rawrxd_master.inc — Master include file for RawrXD assembly modules
; ============================================================================

; Standard calling convention macros
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; Windows x64 calling convention
; RCX, RDX, R8, R9 = integer args
; XMM0-XMM3 = float args
; RAX = return value
; RSP must be 16-byte aligned

; Macro: Preserve registers
PRESERVE_REGS MACRO
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
ENDM

; Macro: Restore registers
RESTORE_REGS MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
ENDM

; Macro: Align stack
ALIGN_STACK MACRO padding:REQ
    sub rsp, padding
ENDM

; Macro: Restore stack
RESTORE_STACK MACRO padding:REQ
    add rsp, padding
ENDM

; Debug breakpoint (int 3)
DEBUG_BREAK MACRO
    int 3
ENDM

; Function prologue with shadow space
FUNCTION_PROLOGUE MACRO localsize:REQ
    push rbp
    mov rbp, rsp
    sub rsp, localsize
    and rsp, NOT 0Fh        ; Align to 16 bytes
ENDM

; Function epilogue
FUNCTION_EPILOGUE MACRO
    mov rsp, rbp
    pop rbp
    ret
ENDM

; ============================================================================
; Common constants
; ============================================================================

; Success/Failure codes
RAWRXD_SUCCESS    equ 1
RAWRXD_FAILURE    equ 0

; Boolean
TRUE              equ 1
FALSE             equ 0

; Memory alignment
CACHE_LINE_SIZE   equ 64
PAGE_SIZE         equ 4096

; ============================================================================
; End of include file
; ============================================================================
