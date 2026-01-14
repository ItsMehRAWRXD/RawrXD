; string_compat.asm - Compatibility aliases for string functions
; Provides strstr_masm and strcmp_masm by wrapping asm_str_* functions

option casemap:none

.code

; External string implementations
EXTERN asm_str_compare:PROC
EXTERN asm_str_find:PROC

; strstr_masm(haystack: rcx, needle: rdx) -> rax (ptr or NULL)
PUBLIC strstr_masm
strstr_masm PROC
    ; Wrapper for asm_str_find
    ; Note: asm_str_find might expect different formats
    ; but for now we provide a minimal implementation
    sub rsp, 32
    call asm_str_find
    add rsp, 32
    ret
strstr_masm ENDP

; strcmp_masm(s1: rcx, s2: rdx) -> rax (bool or result)
PUBLIC strcmp_masm
strcmp_masm PROC
    sub rsp, 32
    call asm_str_compare
    add rsp, 32
    ret
strcmp_masm ENDP

END




