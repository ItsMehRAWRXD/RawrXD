; runtime.asm - Runtime registration for Sovereign Universal Transpiler
; v0.2 - Production: Real function pointer table with proper references

option casemap:none

; The runtime functions are defined in separate modules:
; - print.asm: RuntimePrintString
; - exit.asm: RuntimeExit
; - memory.asm: RuntimeAlloc, RuntimeFree

extrn RuntimePrintString:proc
extrn RuntimeExit:proc
extrn RuntimeAlloc:proc
extrn RuntimeFree:proc

.data
    ; Function IDs
    FUNC_PRINT       equ 1
    FUNC_EXIT        equ 2
    FUNC_ALLOC       equ 3
    FUNC_FREE        equ 4

.code

; RuntimeInit - Initialize runtime function table
; Returns: RAX = 1 on success
RuntimeInit PROC
    ; No initialization needed - functions are linked directly
    mov rax, 1
    ret
RuntimeInit ENDP

; RuntimeGetFunction - Get function pointer by ID
; RCX = function ID
; Returns: RAX = function pointer (0 if invalid)
RuntimeGetFunction PROC
    cmp ecx, FUNC_PRINT
    je get_print
    cmp ecx, FUNC_EXIT
    je get_exit
    cmp ecx, FUNC_ALLOC
    je get_alloc
    cmp ecx, FUNC_FREE
    je get_free
    xor rax, rax
    ret
get_print:
    lea rax, [RuntimePrintString]
    ret
get_exit:
    lea rax, [RuntimeExit]
    ret
get_alloc:
    lea rax, [RuntimeAlloc]
    ret
get_free:
    lea rax, [RuntimeFree]
    ret
RuntimeGetFunction ENDP

end