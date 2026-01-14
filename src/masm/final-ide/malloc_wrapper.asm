; ==========================================================================
; malloc_wrapper.asm - Standard C library malloc/free wrappers for MASM
; ==========================================================================
; Redirects standard malloc/free calls to the project's internal asm_memory
; ==========================================================================

option casemap:none

.code

; External internal allocators
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN asm_realloc:PROC

; Standard malloc(size: rcx)
PUBLIC masm_malloc
masm_malloc PROC
    push rdx
    sub rsp, 32
    
    mov rdx, 16             ; Default 16-byte alignment
    call asm_malloc
    
    add rsp, 32
    pop rdx
    ret
masm_malloc ENDP

; Standard free(ptr: rcx)
PUBLIC masm_free
masm_free PROC
    sub rsp, 32
    call asm_free
    add rsp, 32
    ret
masm_free ENDP

; Standard realloc(ptr: rcx, size: rdx)
PUBLIC masm_realloc
masm_realloc PROC
    push r8
    sub rsp, 32
    
    mov r8, 16              ; Default 16-byte alignment
    call asm_realloc
    
    add rsp, 32
    pop r8
    ret
masm_realloc ENDP

END





